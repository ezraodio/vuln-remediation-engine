"""Core remediation pipeline: ingest → dedupe → route → act → observe."""
from __future__ import annotations

import asyncio
import json
import uuid

import httpx

from . import metrics
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


def _issue_body(finding: Finding, dedupe_key: str, request_id: str) -> str:
    """Render the GitHub issue body.

    Embeds the dedupe key as a visible marker AND the machine-readable
    metadata as an HTML comment. The verifier workflow parses the HTML
    comment so it can filter scanner output down to *this* finding rather
    than flagging the whole repo as still-vulnerable.
    """
    meta = _issue_meta_comment(finding, dedupe_key, request_id)
    lines = [
        meta,
        "> Automatically opened by the vulnerability remediation orchestrator.",
        f"> Dedupe key (do not remove): `{dedupe_key}`",
        f"> Request ID: `{request_id}`",
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
        # Tilde fence: immune to backtick runs inside the excerpt. A raw
        # triple-backtick fence would close early if the scanner-supplied
        # excerpt itself contains ``` (common in docstrings / READMEs).
        lines += ["", "## Code", "~~~", finding.code_excerpt, "~~~"]
    lines += [
        "",
        "## Remediation status",
        "This issue is tracked by the orchestrator. Status transitions will be"
        " posted as comments.",
    ]
    return "\n".join(lines)


def _issue_meta_comment(finding: Finding, dedupe_key: str, request_id: str) -> str:
    """Emit an HTML comment the verifier parses to scope re-scan output.

    The verifier workflow greps for `orchestrator-meta:` and pulls this JSON
    blob out of the tracking issue body to decide whether a given scanner
    hit is *this* finding or an unrelated one.
    """
    meta = {
        "dedupe_key": dedupe_key,
        "request_id": request_id,
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
        # Per-key locks serialize concurrent ingests of the same dedupe_key so
        # only one caller wins the dedupe race and dispatches Devin. The
        # refcount drives eviction without depending on ``asyncio.Lock._waiters``
        # (a private CPython attribute that could change across releases).
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._key_lock_refcount: dict[str, int] = {}
        self._key_locks_guard = asyncio.Lock()

    async def _lock_for(self, key: str) -> asyncio.Lock:
        async with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._key_locks[key] = lock
            self._key_lock_refcount[key] = self._key_lock_refcount.get(key, 0) + 1
            return lock

    async def _release_lock(self, key: str, lock: asyncio.Lock) -> None:
        """Decrement the refcount for ``key`` and evict the lock at zero.

        The refcount is incremented under the guard in ``_lock_for`` and
        decremented here, also under the guard, so a concurrent caller
        mid-acquire can never be left staring at a popped entry.
        """
        async with self._key_locks_guard:
            remaining = self._key_lock_refcount.get(key, 0) - 1
            if remaining > 0:
                self._key_lock_refcount[key] = remaining
                return
            self._key_lock_refcount.pop(key, None)
            if self._key_locks.get(key) is lock:
                self._key_locks.pop(key, None)

    # ------------------------------------------------------------------ #
    # Public entrypoint                                                  #
    # ------------------------------------------------------------------ #

    async def handle_finding(
        self, finding: Finding, *, source: str, request_id: str | None = None
    ) -> IngestResult:
        # Callers that don't supply a request_id (e.g. scripted backfills,
        # tests) still get correlation coverage via a freshly minted UUID so
        # every finding ends up with one.
        rid = request_id or uuid.uuid4().hex
        key = finding.dedupe_key()
        lock = await self._lock_for(key)
        try:
            async with lock:
                return await self._handle_finding_locked(
                    finding, key=key, source=source, request_id=rid
                )
        finally:
            await self._release_lock(key, lock)

    async def _handle_finding_locked(
        self, finding: Finding, *, key: str, source: str, request_id: str
    ) -> IngestResult:
        logger = log.bind(
            dedupe_key=key,
            rule=finding.rule_id,
            severity=finding.severity.value,
            request_id=request_id,
        )
        logger.info("finding_received", scanner=finding.scanner, source=source)
        metrics.findings_ingested.labels(
            kind=finding.kind.value, severity=finding.severity.value
        ).inc()

        if (local_hit := self._deduped_locally(key)) is not None:
            logger.info("dedupe_hit_local", status=local_hit.status.value)
            metrics.findings_deduped.labels(layer="local").inc()
            return local_hit

        # Open-issue dedupe covers the case where SQLite was dropped but the
        # GitHub issue still exists — prevents a duplicate from being filed.
        if (
            issue_hit := await self._deduped_by_issue(finding, key, request_id=request_id)
        ) is not None:
            logger.info("dedupe_hit_github_issue")
            metrics.findings_deduped.labels(layer="github_issue").inc()
            return issue_hit

        if (
            session_hit := await self._deduped_by_session(finding, key, request_id=request_id)
        ) is not None:
            logger.info("dedupe_hit_active_session")
            metrics.findings_deduped.labels(layer="active_session").inc()
            return session_hit

        decision = self.router.decide(finding)
        logger.info(
            "routing_decision", action=decision.action, reason=decision.reason
        )

        if decision.action == "skip":
            self._record(
                finding, key, status=RemediationStatus.FILTERED, request_id=request_id
            )
            self.store.log_event(key, "filtered", {"reason": decision.reason})
            metrics.findings_filtered.labels(reason="severity_floor").inc()
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason=decision.reason,
            )

        # Dry-run short-circuits *before* any side effects on the target repo:
        # no issue opened, no Devin session dispatched. This is the whole
        # point of DRY_RUN=true — inspect what we would do without touching
        # GitHub or Devin.
        if self.settings.dry_run:
            self._record(
                finding, key, status=RemediationStatus.FILTERED, request_id=request_id
            )
            self.store.log_event(key, "dry_run_skip", {"reason": decision.reason})
            metrics.findings_filtered.labels(reason="dry_run").inc()
            return IngestResult(
                dedupe_key=key,
                status=RemediationStatus.FILTERED,
                reason="DRY_RUN=true",
            )

        # Create the tracking issue before dispatching so the Devin prompt can
        # reference the issue number (Devin's PR will link back to it).
        issue = await self.gh.create_issue(
            finding.repo,
            title=finding.human_title(),
            body=_issue_body(finding, key, request_id),
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
            request_id=request_id,
        )
        self.store.log_event(key, "issue_created", {"url": issue["html_url"]})

        return await self._dispatch_devin(
            finding=finding,
            key=key,
            issue=issue,
            decision_reason=decision.reason,
            request_id=request_id,
            logger=logger,
        )

    # ------------------------------------------------------------------ #
    # Reconciliation (periodic poll)                                     #
    # ------------------------------------------------------------------ #

    def should_reconcile(self, rec: RemediationRecord) -> bool:
        """Whether ``/reconcile`` should poll Devin for this record.

        Terminal rows (FAILED / FILTERED / DEDUPED / VERIFIED_FIXED /
        VERIFICATION_FAILED) have nothing left to advance; polling them on
        every cron tick would burn Devin API budget for no state change.
        ``resolved_at`` alone is not a sufficient signal because only
        VERIFIED_FIXED sets it.
        """
        return bool(rec.session_id) and not rec.status.is_terminal()

    async def reconcile_session(self, rec: RemediationRecord) -> None:
        """Poll Devin + GitHub to advance a record through the state machine.

        Delegates each distinct signal to a narrow helper:
          * new PR on the session                 → :meth:`_record_pr_opened`
          * session ended without producing a PR  → :meth:`_record_session_failed`
          * PR aged past the stale thresholds     → :meth:`_reconcile_stale_pr`
        """
        if not self.should_reconcile(rec):
            return
        logger = log.bind(
            dedupe_key=rec.dedupe_key,
            rule=rec.finding.rule_id,
            request_id=rec.request_id,
            session=rec.session_id,
        )
        try:
            session = await self.devin.get_session(rec.session_id)
        except httpx.HTTPError as e:
            logger.warning("reconcile_get_session_failed", err=str(e))
            return

        self._persist_acu_cost(rec, session)

        prs = session.get("pull_requests") or []
        if prs and not rec.pr_url:
            await self._record_pr_opened(rec, prs[0])
            return

        # NEEDS_ATTENTION is reached only by aging past the flag threshold,
        # so we must keep polling that PR — a human might still merge or close
        # it. Without this, once flagged, the record is invisible to the
        # reconciler forever even though the PR could legitimately resolve.
        if rec.status in {
            RemediationStatus.PR_OPENED,
            RemediationStatus.NEEDS_ATTENTION,
        } and rec.pr_url:
            await self._reconcile_stale_pr(rec, logger)
            return

        if not self.devin.session_is_active(session) and not prs and not rec.pr_url:
            self._record_session_failed(rec, session, logger)

    async def _best_effort_comment(
        self,
        dedupe_key: str,
        repo: str,
        issue_number: int,
        body: str,
        *,
        event: str,
    ) -> None:
        """Post a tracking-issue comment without letting GitHub flaps leak out.

        The calling site has already persisted a state transition (FAILED,
        SESSION_RUNNING, PR_OPENED, …); the comment is operator-visibility
        sugar. If GitHub is down we log the failure through the store audit
        log and the structured logger so operators can still trace what
        happened, but we never propagate the error to the HTTP handler — that
        would 500 a request whose actual work has already succeeded and
        prompt the scanner/CI to retry work we've already recorded.
        """
        try:
            await self.gh.comment_issue(repo, issue_number, body)
        except httpx.HTTPError as err:
            log.warning(event, err=str(err), dedupe_key=dedupe_key)
            self.store.log_event(dedupe_key, event, {"err": str(err)})

    def _persist_acu_cost(self, rec: RemediationRecord, session: dict) -> None:
        """Write Devin's current ACU total to the record if it has grown.

        Devin's running total is monotonic; always take the latest report.
        The histogram is intentionally NOT observed here — a session reconciled
        five times with running totals (1, 2, 3, 4, 5) would generate five
        samples summing to 15 instead of one sample of 5, wrecking percentile
        and average math. See `_observe_terminal_acu_cost`.
        """
        acu = self.devin.session_acu_cost(session)
        if acu is None or (rec.acu_cost is not None and acu <= rec.acu_cost):
            return
        self.store.update_status(rec.dedupe_key, rec.status, acu_cost=acu)
        self.store.log_event(rec.dedupe_key, "acu_cost_updated", {"acu": acu})
        rec.acu_cost = acu

    @staticmethod
    def _observe_terminal_acu_cost(rec: RemediationRecord) -> None:
        """Emit exactly one ACU-per-session sample at the terminal transition.

        Called from every path that drives a record into a terminal status
        (FAILED / MERGED_UNVERIFIED / HUMAN_REJECTED; VERIFIED_FIXED lives in
        the verifier). Terminal records are excluded from `should_reconcile`,
        so re-entry here is impossible — one sample per session.
        """
        if rec.acu_cost is not None:
            metrics.acu_cost_per_session.observe(rec.acu_cost)

    async def _record_pr_opened(self, rec: RemediationRecord, pr: dict) -> None:
        pr_url = pr.get("url") or pr.get("html_url") or str(pr)
        self.store.update_status(
            rec.dedupe_key,
            RemediationStatus.PR_OPENED,
            pr_url=pr_url,
            mark_pr_opened=True,
        )
        self.store.log_event(rec.dedupe_key, "pr_opened", {"url": pr_url})
        if rec.issue_number:
            await self._best_effort_comment(
                rec.dedupe_key,
                rec.finding.repo,
                rec.issue_number,
                f":sparkles: Devin opened PR: {pr_url}",
                event="pr_opened_comment_failed",
            )

    def _record_session_failed(
        self, rec: RemediationRecord, session: dict, logger
    ) -> None:
        self.store.update_status(rec.dedupe_key, RemediationStatus.FAILED)
        self.store.log_event(
            rec.dedupe_key, "session_ended_no_pr", {"status": session.get("status")}
        )
        logger.info("session_ended_no_pr", status=session.get("status"))
        self._observe_terminal_acu_cost(rec)

    async def _reconcile_stale_pr(self, rec: RemediationRecord, logger) -> None:
        """Advance a long-open PR through the terminal states.

        Three possible transitions based on GitHub's PR state:
          * merged      → MERGED_UNVERIFIED (a human merged without a verify signal)
          * closed      → HUMAN_REJECTED (closed without merge)
          * still open  → NEEDS_ATTENTION if past ``stale_pr_flag_hours``

        The WARN threshold is not a state change — it only surfaces the row
        on the dashboard as "stale" so operators can triage before we
        escalate to NEEDS_ATTENTION.
        """
        age_hours = rec.pr_age_hours()
        state: dict | None = None
        try:
            state = await self.gh.get_pr_state(rec.pr_url or "")
        except httpx.HTTPError as e:
            logger.warning("reconcile_pr_state_failed", err=str(e), pr=rec.pr_url)

        if state is not None:
            if state.get("merged"):
                self.store.update_status(
                    rec.dedupe_key,
                    RemediationStatus.MERGED_UNVERIFIED,
                    mark_resolved=True,
                )
                self.store.log_event(
                    rec.dedupe_key, "pr_merged_unverified", {"pr": rec.pr_url}
                )
                logger.info("pr_merged_unverified", pr=rec.pr_url)
                self._observe_terminal_acu_cost(rec)
                return
            if state.get("state") == "closed":
                self.store.update_status(
                    rec.dedupe_key,
                    RemediationStatus.HUMAN_REJECTED,
                    mark_resolved=True,
                )
                self.store.log_event(
                    rec.dedupe_key, "pr_closed_without_merge", {"pr": rec.pr_url}
                )
                logger.info("pr_closed_without_merge", pr=rec.pr_url)
                self._observe_terminal_acu_cost(rec)
                return

        # Age-based NEEDS_ATTENTION must still fire when GitHub is
        # unreachable or the PR was deleted — a silent-no-op would strand
        # the record in PR_OPENED forever with zero operator signal.
        if (
            age_hours >= self.settings.stale_pr_flag_hours
            and rec.status != RemediationStatus.NEEDS_ATTENTION
        ):
            self.store.update_status(rec.dedupe_key, RemediationStatus.NEEDS_ATTENTION)
            self.store.log_event(
                rec.dedupe_key,
                "pr_flagged_stale",
                {"pr": rec.pr_url, "age_hours": round(age_hours, 1)},
            )
            logger.warning(
                "pr_flagged_stale", pr=rec.pr_url, age_hours=round(age_hours, 1)
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
        request_id: str | None = None,
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
            request_id=request_id,
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
        self, finding: Finding, key: str, *, request_id: str
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
            request_id=request_id,
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
        self, finding: Finding, key: str, *, request_id: str
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
            request_id=request_id,
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
        request_id: str,
        logger,
    ) -> IngestResult:
        prompt = build_prompt(
            finding,
            target_repo=finding.repo,
            issue_number=issue["number"],
            base_branch=self.settings.target_base_branch,
        )
        try:
            created = await self.devin.create_session(
                prompt=prompt,
                title=f"[auto] Remediate {finding.rule_id} in {finding.repo}",
                tags=_session_tags(finding, key, request_id),
                idempotent=True,
            )
        except httpx.HTTPError as e:
            return await self._handle_dispatch_failure(
                finding=finding, key=key, issue=issue, error=e, logger=logger
            )
        return await self._record_dispatch_success(
            finding=finding,
            key=key,
            issue=issue,
            decision_reason=decision_reason,
            created=created,
        )

    async def _handle_dispatch_failure(
        self,
        *,
        finding: Finding,
        key: str,
        issue: dict,
        error: httpx.HTTPError,
        logger,
    ) -> IngestResult:
        logger.error("devin_dispatch_failed", err=str(error))
        metrics.dispatch_failures.labels(scanner=finding.scanner).inc()
        self.store.update_status(key, RemediationStatus.FAILED)
        self.store.log_event(key, "devin_dispatch_failed", {"err": str(error)})
        await self._best_effort_comment(
            key,
            finding.repo,
            issue["number"],
            f":warning: Failed to dispatch Devin session: `{error}`",
            event="devin_dispatch_failed_comment_failed",
        )
        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.FAILED,
            reason=f"Devin dispatch failed: {error}",
            issue_url=issue["html_url"],
        )

    async def _record_dispatch_success(
        self,
        *,
        finding: Finding,
        key: str,
        issue: dict,
        decision_reason: str,
        created: dict,
    ) -> IngestResult:
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
        metrics.findings_dispatched.labels(
            kind=finding.kind.value, severity=finding.severity.value
        ).inc()
        await self._best_effort_comment(
            key,
            finding.repo,
            issue["number"],
            f":robot: Devin session started: {session_url}\n\n"
            f"Routing reason: _{decision_reason}_",
            event="devin_dispatched_comment_failed",
        )
        return IngestResult(
            dedupe_key=key,
            status=RemediationStatus.DISPATCHED,
            reason=decision_reason,
            issue_url=issue["html_url"],
            session_id=session_id,
            session_url=session_url,
        )


_ORCHESTRATOR_SOURCE_TAG = "source:vuln-remediation-orchestrator"


def _session_tags(finding: Finding, key: str, request_id: str) -> list[str]:
    """Tags attached to every Devin session the orchestrator spawns.

    The first tag (``vuln:<key>``) is the dedupe-layer-3 anchor: the
    pipeline searches by this exact tag to discover an active session
    already working on the same finding.
    """
    return [
        f"vuln:{key}",
        f"rule:{finding.rule_id}",
        f"severity:{finding.severity.value}",
        f"repo:{finding.repo}",
        f"req:{request_id}",
        _ORCHESTRATOR_SOURCE_TAG,
    ]
