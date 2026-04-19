"""Core remediation pipeline: ingest → dedupe → route → act → observe."""
from __future__ import annotations

from datetime import datetime

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

log = get_logger("pipeline")


def _issue_body(finding: Finding, dedupe_key: str, settings: Settings) -> str:  # noqa: ARG001
    lines = [
        "> Automatically opened by the vulnerability remediation orchestrator.",
        f"> Dedupe key (do not remove): `{dedupe_key}`",
        "",
        f"**Rule:** `{finding.rule_id}`",
        f"**Severity:** {finding.severity.value}"
        + (f" (CVSS {finding.cvss})" if finding.cvss else ""),
        f"**Scanner:** {finding.scanner}",
    ]
    if finding.kind == FindingKind.DEP_CVE:
        fixed = ", ".join(finding.fixed_versions) if finding.fixed_versions else "no patched version yet"
        lines += [
            f"**Package:** `{finding.package_name}=={finding.installed_version}` ({finding.package_ecosystem})",
            f"**Fixed in:** {fixed}",
            f"**Manifest:** `{finding.manifest_path}`",
        ]
    else:
        lines += [
            f"**Location:** `{finding.file_path}:{finding.line}`",
        ]
    if finding.advisory_url:
        lines.append(f"**Advisory:** {finding.advisory_url}")
    if finding.description:
        lines += ["", "## Description", finding.description]
    if finding.code_excerpt:
        lines += ["", "## Code", "```", finding.code_excerpt, "```"]
    lines += [
        "",
        "## Remediation status",
        "This issue is tracked by the orchestrator. Status transitions will be posted as comments.",
    ]
    return "\n".join(lines)


class RemediationPipeline:
    def __init__(
        self,
        *,
        settings: Settings,
        store: Store,
        devin: DevinClient,
        gh: GitHubClient,
        router: Router,
    ):
        self.settings = settings
        self.store = store
        self.devin = devin
        self.gh = gh
        self.router = router

    # -------- the single public entrypoint --------

    async def handle_finding(self, finding: Finding, *, source: str) -> IngestResult:
        key = finding.dedupe_key()
        logger = log.bind(dedupe_key=key, rule=finding.rule_id, severity=finding.severity.value)
        logger.info("finding_received", scanner=finding.scanner, source=source)

        # 1) Local dedupe via SQLite.
        existing = self.store.get(key)
        if existing is not None:
            logger.info("dedupe_hit_local", status=existing.status.value)
            self.store.log_event(key, "dedupe_hit_local", {"existing_status": existing.status.value})
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.DEDUPED,
                reason=f"Already tracked: status={existing.status.value}",
                issue_url=existing.issue_url,
                session_id=existing.session_id,
                session_url=existing.session_url,
                pr_url=existing.pr_url,
            )

        # 2) Open-issue dedupe (covers restarts where SQLite was dropped).
        open_issue = await self.gh.find_open_issue_by_label(
            finding.repo, self.settings.issue_label, marker=f"`{key}`"
        )
        if open_issue is not None:
            rec = RemediationRecord(
                dedupe_key=key,
                finding=finding,
                status=RemediationStatus.DEDUPED,
                issue_number=open_issue["number"],
                issue_url=open_issue["html_url"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.store.upsert(rec)
            self.store.log_event(
                key, "dedupe_hit_github_issue", {"issue": open_issue["html_url"]}
            )
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.DEDUPED,
                reason="Open GitHub issue already exists for this finding",
                issue_url=open_issue["html_url"],
            )

        # 3) Active-session dedupe.
        tag = f"vuln:{key}"
        active = await self.devin.list_sessions_by_tag(tag)
        active = [s for s in active if self.devin.session_is_active(s)]
        if active:
            s = active[0]
            rec = RemediationRecord(
                dedupe_key=key,
                finding=finding,
                status=RemediationStatus.SESSION_RUNNING,
                session_id=s.get("session_id"),
                session_url=s.get("url"),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.store.upsert(rec)
            self.store.log_event(key, "dedupe_hit_active_session", {"session": s.get("url")})
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.DEDUPED,
                reason="Active Devin session already working on this finding",
                session_id=s.get("session_id"),
                session_url=s.get("url"),
            )

        # 4) Route.
        decision = self.router.decide(finding)
        logger.info("routing_decision", action=decision.action, reason=decision.reason)

        # Severity filter → record & stop.
        if decision.action == "skip":
            rec = RemediationRecord(
                dedupe_key=key,
                finding=finding,
                status=RemediationStatus.FILTERED,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            self.store.upsert(rec)
            self.store.log_event(key, "filtered", {"reason": decision.reason})
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason=decision.reason,
            )

        # 5) Create the tracking issue first so the Devin prompt can reference it.
        now = datetime.utcnow()
        issue = await self.gh.create_issue(
            finding.repo,
            title=finding.human_title(),
            body=_issue_body(finding, key, self.settings),
            labels=[self.settings.issue_label, f"severity:{finding.severity.value.lower()}"],
        )
        rec = RemediationRecord(
            dedupe_key=key,
            finding=finding,
            status=RemediationStatus.DISPATCHED,
            issue_number=issue["number"],
            issue_url=issue["html_url"],
            created_at=now,
            updated_at=now,
        )
        self.store.upsert(rec)
        self.store.log_event(key, "issue_created", {"url": issue["html_url"]})

        if self.settings.dry_run:
            self.store.update_status(key, RemediationStatus.FILTERED)
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason="DRY_RUN=true",
                issue_url=issue["html_url"],
            )

        # 6) Open a direct bump PR (not implemented in v1 of the system; we
        # prefer dispatching Devin so he also runs CI locally). For now this
        # path records a note and falls through to dispatching Devin with a
        # bump-focused prompt.
        if decision.action == "open_bump_pr":
            await self.gh.comment_issue(
                finding.repo,
                issue["number"],
                f"Router decision: **open_bump_pr** (target `{decision.bump_target}`). "
                f"Falling back to Devin dispatch so tests run against the bump.",
            )

        # 7) Dispatch Devin.
        prompt = build_prompt(finding, target_repo=finding.repo, issue_number=issue["number"])
        title = f"[auto] Remediate {finding.rule_id} in {finding.repo}"
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
        except Exception as e:  # noqa: BLE001
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
            key, "devin_dispatched", {"session_id": session_id, "session_url": session_url}
        )
        await self.gh.comment_issue(
            finding.repo,
            issue["number"],
            f":robot: Devin session started: {session_url}\n\n"
            f"Routing reason: _{decision.reason}_",
        )

        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DISPATCHED,
            reason=decision.reason,
            issue_url=issue["html_url"],
            session_id=session_id,
            session_url=session_url,
        )

    # -------- used by periodic reconciler --------

    async def reconcile_session(self, rec: RemediationRecord) -> None:
        """Poll Devin to update session state; link PR if one appeared."""
        if not rec.session_id:
            return
        try:
            s = await self.devin.get_session(rec.session_id)
        except Exception as e:  # noqa: BLE001
            log.warning("reconcile_get_session_failed", err=str(e), session=rec.session_id)
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
        # If the session stopped without a PR, mark failed.
        if not self.devin.session_is_active(s) and not prs and rec.status != RemediationStatus.FAILED:
            self.store.update_status(rec.dedupe_key, RemediationStatus.FAILED)
            self.store.log_event(rec.dedupe_key, "session_ended_no_pr", {"status": s.get("status")})
