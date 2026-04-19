"""Core remediation pipeline: ingest → dedupe → route → act → observe."""
from __future__ import annotations

import json

import httpx

from .config import Settings
from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .logging_config import get_logger
from .models import (
    Finding,
    FindingKind,
    IngestResult,
    RemediationRecord,
    RemediationStatus,
)
from .prompts import build_prompt
from .router import Router
from .time_utils import now_utc

log = get_logger("pipeline")


def _issue_body(finding: Finding, dedupe_key: str) -> str:
    """Render the GitHub issue body.

    Embeds the dedupe key as a visible marker AND the machine-readable
    metadata as an HTML comment. The verifier workflow parses the HTML
    comment so it can filter scanner output down to *this* finding rather
    than flagging the whole repo as still-vulnerable.
    """
    meta = _issue_meta_comment(finding, dedupe_key)
    lines = [
        meta,
        "> Automatically opened by the vulnerability remediation orchestrator.",
        f"> Dedupe key (do not remove): `{dedupe_key}`",
        "",
        f"**Rule:** `{finding.rule_id}`",
        f"**Severity:** {finding.severity.value}"
        + (f" (CVSS {finding.cvss})" if finding.cvss else ""),
        f"**Scanner:** {finding.scanner}",
    ]
    if finding.kind == FindingKind.DEP_CVE:
        fixed = ", ".join(finding.fixed_versions) or "no patched version yet"
        lines += [
            f"**Package:** `{finding.package_name}=={finding.installed_version}`"
            f" ({finding.package_ecosystem})",
            f"**Fixed in:** {fixed}",
            f"**Manifest:** `{finding.manifest_path}`",
        ]
    else:
        lines.append(f"**Location:** `{finding.file_path}:{finding.line}`")
    if finding.advisory_url:
        lines.append(f"**Advisory:** {finding.advisory_url}")
    if finding.description:
        lines += ["", "## Description", finding.description]
    if finding.code_excerpt:
        lines += ["", "## Code", "```", finding.code_excerpt, "```"]
    lines += [
        "",
        "## Remediation status",
        "This issue is tracked by the orchestrator. Status transitions will be"
        " posted as comments.",
    ]
    return "\n".join(lines)


def _issue_meta_comment(finding: Finding, dedupe_key: str) -> str:
    """Emit an HTML comment the verifier parses to scope re-scan output.

    The verifier workflow greps for `orchestrator-meta:` and pulls this JSON
    blob out of the tracking issue body to decide whether a given scanner
    hit is *this* finding or an unrelated one.
    """
    meta = {
        "dedupe_key": dedupe_key,
        "kind": finding.kind.value,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "line": finding.line,
        "package_name": finding.package_name,
        "scanner": finding.scanner,
    }
    return f"<!-- orchestrator-meta:{json.dumps(meta, separators=(',', ':'))} -->"


class RemediationPipeline:
    """Orchestrates the ingest → dedupe → route → act → observe flow.

    The single public entrypoint is :meth:`handle_finding`; everything else is
    a private helper. State is persisted in SQLite (via :class:`Store`) and
    mirrored into GitHub issues and Devin sessions.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        store: Store,
        devin: DevinClient,
        gh: GitHubClient,
        router: Router,
    ) -> None:
        self.settings = settings
        self.store = store
        self.devin = devin
        self.gh = gh
        self.router = router

    # ------------------------------------------------------------------ #
    # Public entrypoint                                                  #
    # ------------------------------------------------------------------ #

    async def handle_finding(self, finding: Finding, *, source: str) -> IngestResult:
        key = finding.dedupe_key()
        logger = log.bind(
            dedupe_key=key, rule=finding.rule_id, severity=finding.severity.value
        )
        logger.info("finding_received", scanner=finding.scanner, source=source)

        if (local_hit := self._deduped_locally(key)) is not None:
            logger.info("dedupe_hit_local", status=local_hit.status.value)
            return local_hit

        # Open-issue dedupe covers the case where SQLite was dropped but the
        # GitHub issue still exists — prevents a duplicate from being filed.
        if (issue_hit := await self._deduped_by_issue(finding, key)) is not None:
            logger.info("dedupe_hit_github_issue")
            return issue_hit

        if (session_hit := await self._deduped_by_session(finding, key)) is not None:
            logger.info("dedupe_hit_active_session")
            return session_hit

        decision = self.router.decide(finding)
        logger.info(
            "routing_decision", action=decision.action, reason=decision.reason
        )

        if decision.action == "skip":
            self._record(
                finding, key, status=RemediationStatus.FILTERED
            )
            self.store.log_event(key, "filtered", {"reason": decision.reason})
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason=decision.reason,
            )

        # Create the tracking issue before dispatching so the Devin prompt can
        # reference the issue number (Devin's PR will link back to it).
        issue = await self.gh.create_issue(
            finding.repo,
            title=finding.human_title(),
            body=_issue_body(finding, key),
            labels=[
                self.settings.issue_label,
                f"severity:{finding.severity.value.lower()}",
            ],
        )
        self._record(
            finding,
            key,
            status=RemediationStatus.DISPATCHED,
            issue_number=issue["number"],
            issue_url=issue["html_url"],
        )
        self.store.log_event(key, "issue_created", {"url": issue["html_url"]})

        if self.settings.dry_run:
            self.store.update_status(key, RemediationStatus.FILTERED)
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason="DRY_RUN=true",
                issue_url=issue["html_url"],
            )

        return await self._dispatch_devin(
            finding=finding,
            key=key,
            issue=issue,
            decision_reason=decision.reason,
            logger=logger,
        )

    # ------------------------------------------------------------------ #
    # Reconciliation (periodic poll)                                     #
    # ------------------------------------------------------------------ #

    async def reconcile_session(self, rec: RemediationRecord) -> None:
        """Poll Devin to update session state; link PR if one appeared."""
        if not rec.session_id or rec.status.is_terminal():
            return
        try:
            s = await self.devin.get_session(rec.session_id)
        except httpx.HTTPError as e:
            log.warning(
                "reconcile_get_session_failed", err=str(e), session=rec.session_id
            )
            return
        prs = s.get("pull_requests") or []
        if prs and not rec.pr_url:
            pr_url = prs[0].get("url") or prs[0].get("html_url") or str(prs[0])
            self.store.update_status(
                rec.dedupe_key, RemediationStatus.PR_OPENED, pr_url=pr_url
            )
            self.store.log_event(rec.dedupe_key, "pr_opened", {"url": pr_url})
            if rec.issue_number:
                await self.gh.comment_issue(
                    rec.finding.repo,
                    rec.issue_number,
                    f":sparkles: Devin opened PR: {pr_url}",
                )
            return
        if not self.devin.session_is_active(s) and not prs and not rec.pr_url:
            self.store.update_status(rec.dedupe_key, RemediationStatus.FAILED)
            self.store.log_event(
                rec.dedupe_key, "session_ended_no_pr", {"status": s.get("status")}
            )

    # ------------------------------------------------------------------ #
    # Private helpers                                                    #
    # ------------------------------------------------------------------ #

    def _record(
        self,
        finding: Finding,
        key: str,
        *,
        status: RemediationStatus,
        issue_number: int | None = None,
        issue_url: str | None = None,
        session_id: str | None = None,
        session_url: str | None = None,
    ) -> RemediationRecord:
        """Create+persist a RemediationRecord with consistent timestamps.

        Centralized so every insertion path uses the same shape; also the only
        place we call `now_utc()` for record creation.
        """
        now = now_utc()
        rec = RemediationRecord(
            dedupe_key=key,
            finding=finding,
            status=status,
            issue_number=issue_number,
            issue_url=issue_url,
            session_id=session_id,
            session_url=session_url,
            created_at=now,
            updated_at=now,
        )
        self.store.upsert(rec)
        return rec

    def _deduped_locally(self, key: str) -> IngestResult | None:
        existing = self.store.get(key)
        if existing is None:
            return None
        self.store.log_event(
            key, "dedupe_hit_local", {"existing_status": existing.status.value}
        )
        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DEDUPED,
            reason=f"Already tracked: status={existing.status.value}",
            issue_url=existing.issue_url,
            session_id=existing.session_id,
            session_url=existing.session_url,
            pr_url=existing.pr_url,
        )

    async def _deduped_by_issue(
        self, finding: Finding, key: str
    ) -> IngestResult | None:
        open_issue = await self.gh.find_open_issue_by_label(
            finding.repo, self.settings.issue_label, marker=f"`{key}`"
        )
        if open_issue is None:
            return None
        self._record(
            finding,
            key,
            status=RemediationStatus.DEDUPED,
            issue_number=open_issue["number"],
            issue_url=open_issue["html_url"],
        )
        self.store.log_event(
            key, "dedupe_hit_github_issue", {"issue": open_issue["html_url"]}
        )
        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DEDUPED,
            reason="Open GitHub issue already exists for this finding",
            issue_url=open_issue["html_url"],
        )

    async def _deduped_by_session(
        self, finding: Finding, key: str
    ) -> IngestResult | None:
        tag = f"vuln:{key}"
        candidates = await self.devin.list_sessions_by_tag(tag)
        active = [s for s in candidates if self.devin.session_is_active(s)]
        if not active:
            return None
        s = active[0]
        self._record(
            finding,
            key,
            status=RemediationStatus.SESSION_RUNNING,
            session_id=s.get("session_id"),
            session_url=s.get("url"),
        )
        self.store.log_event(
            key, "dedupe_hit_active_session", {"session": s.get("url")}
        )
        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DEDUPED,
            reason="Active Devin session already working on this finding",
            session_id=s.get("session_id"),
            session_url=s.get("url"),
        )

    async def _dispatch_devin(
        self,
        *,
        finding: Finding,
        key: str,
        issue: dict,
        decision_reason: str,
        logger,
    ) -> IngestResult:
        prompt = build_prompt(
            finding,
            target_repo=finding.repo,
            issue_number=issue["number"],
            base_branch=self.settings.target_base_branch,
        )
        title = f"[auto] Remediate {finding.rule_id} in {finding.repo}"
        tag = f"vuln:{key}"
        try:
            created = await self.devin.create_session(
                prompt=prompt,
                title=title,
                tags=[
                    tag,
                    f"rule:{finding.rule_id}",
                    f"severity:{finding.severity.value}",
                    f"repo:{finding.repo}",
                    "source:vuln-remediation-orchestrator",
                ],
                idempotent=True,
            )
        except httpx.HTTPError as e:
            logger.error("devin_dispatch_failed", err=str(e))
            self.store.update_status(key, RemediationStatus.FAILED)
            self.store.log_event(key, "devin_dispatch_failed", {"err": str(e)})
            await self.gh.comment_issue(
                finding.repo,
                issue["number"],
                f":warning: Failed to dispatch Devin session: `{e}`",
            )
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FAILED,
                reason=f"Devin dispatch failed: {e}",
                issue_url=issue["html_url"],
            )

        session_id = created.get("session_id")
        session_url = created.get("url")
        self.store.update_status(
            key,
            RemediationStatus.SESSION_RUNNING,
            session_id=session_id,
            session_url=session_url,
        )
        self.store.log_event(
            key,
            "devin_dispatched",
            {"session_id": session_id, "session_url": session_url},
        )
        await self.gh.comment_issue(
            finding.repo,
            issue["number"],
            f":robot: Devin session started: {session_url}\n\n"
            f"Routing reason: _{decision_reason}_",
        )

        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DISPATCHED,
            reason=decision_reason,
            issue_url=issue["html_url"],
            session_id=session_id,
            session_url=session_url,
        )
