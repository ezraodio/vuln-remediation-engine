"""Verification loop.

When Devin opens a PR, we rerun the scanner against the PR branch (either
inline or delegated to a verification CI workflow). Results are reported back
into the Devin session via /sessions/{id}/message when verification fails,
so Devin iterates instead of us spawning a brand-new session.

In the v1 implementation, verification is **triggered externally** by the
verification GitHub Action (see scanner/verify-devin-pr.yml) which POSTs its
result to /verify/result. That keeps the orchestrator itself stateless and
free of language-specific scanning deps.
"""
from __future__ import annotations

from enum import StrEnum

import httpx
from pydantic import BaseModel

from . import metrics
from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .logging_config import get_logger
from .models import RemediationStatus
from .time_utils import now_utc

log = get_logger("verifier")


class VerifyOutcome(StrEnum):
    CLEAN = "clean"                 # finding no longer reported
    STILL_VULNERABLE = "still_vuln" # finding still present on branch


class VerifyReport(BaseModel):
    dedupe_key: str
    pr_url: str | None = None
    outcome: VerifyOutcome
    scanner_output: str | None = None


class Verifier:
    def __init__(self, *, store: Store, devin: DevinClient, gh: GitHubClient):
        self.store = store
        self.devin = devin
        self.gh = gh

    async def _best_effort_comment(
        self,
        dedupe_key: str,
        repo: str,
        issue_number: int,
        body: str,
        *,
        event: str,
        logger,
    ) -> None:
        """Post an operator-visibility comment; log on failure but never raise.

        The verification status transition has already been persisted before
        we get here. Propagating a transient GitHub error back to
        /verify/result would 500 the scanner's CI POST, which would then
        retry — and without the terminal-status guard above, the retry would
        double-count metrics. Logging + an audit-log event keeps the failure
        debuggable without destabilising the endpoint contract.
        """
        try:
            await self.gh.comment_issue(repo, issue_number, body)
        except httpx.HTTPError as err:
            logger.warning(event, err=str(err))
            self.store.log_event(dedupe_key, event, {"err": str(err)})

    async def handle_report(self, report: VerifyReport) -> None:
        rec = self.store.get(report.dedupe_key)
        if not rec:
            log.warning("verify_report_unknown_key", key=report.dedupe_key)
            return

        logger = log.bind(
            dedupe_key=report.dedupe_key,
            rule=rec.finding.rule_id,
            outcome=report.outcome.value,
            pr=report.pr_url,
        )

        # CI workflows retry on transient 5xx, so /verify/result can be
        # delivered more than once for the same dedupe_key. Once we've
        # landed on a terminal status (VERIFIED_FIXED / HUMAN_REJECTED /
        # FAILED), replaying the body would double-count verify_outcomes,
        # re-observe MTTR, and emit a duplicate verify_report event.
        if rec.status.is_terminal():
            logger.info("verify_report_ignored_terminal", status=rec.status.value)
            return

        logger.info("verify_report_received")
        self.store.log_event(
            report.dedupe_key,
            "verify_report",
            {"outcome": report.outcome.value, "pr": report.pr_url},
        )
        metrics.verify_outcomes.labels(outcome=report.outcome.value).inc()
        latency = (now_utc() - rec.created_at).total_seconds()
        metrics.verify_latency_seconds.observe(latency)

        if report.outcome == VerifyOutcome.CLEAN:
            self.store.update_status(
                report.dedupe_key,
                RemediationStatus.VERIFIED_FIXED,
                pr_url=report.pr_url,
                mark_resolved=True,
            )
            metrics.mttr_seconds.observe(latency)
            if rec.issue_number:
                await self._best_effort_comment(
                    report.dedupe_key,
                    rec.finding.repo,
                    rec.issue_number,
                    f":white_check_mark: Verified fix on {report.pr_url}: "
                    f"`{rec.finding.rule_id}` no longer reported by the scanner.",
                    event="verify_fixed_comment_failed",
                    logger=logger,
                )
            return

        if report.outcome == VerifyOutcome.STILL_VULNERABLE:
            self.store.update_status(
                report.dedupe_key,
                RemediationStatus.VERIFICATION_FAILED,
                pr_url=report.pr_url,
            )
            if rec.issue_number:
                await self._best_effort_comment(
                    report.dedupe_key,
                    rec.finding.repo,
                    rec.issue_number,
                    f":x: Verification failed on {report.pr_url}: "
                    f"`{rec.finding.rule_id}` is still reported on your branch. "
                    f"Messaging the session to iterate.",
                    event="verify_failed_comment_failed",
                    logger=logger,
                )
            # Feed the failure back into the running session instead of
            # starting a new one. Devin will see the message and iterate.
            # Swallow send_message HTTP failures: the session may have been
            # archived, but we've already persisted VERIFICATION_FAILED above
            # — we must not 500 the /verify/result endpoint over a best-effort
            # notification or the scanner workflow will retry a fix-loop that
            # has already been recorded.
            if rec.session_id:
                excerpt = (report.scanner_output or "")[:4000]
                try:
                    await self.devin.send_message(
                        rec.session_id,
                        (
                            f"Verification re-scan reports that `{rec.finding.rule_id}` is "
                            f"STILL present on your branch ({report.pr_url}). Please iterate "
                            f"and push another commit. Scanner output follows:\n\n"
                            f"```\n{excerpt}\n```"
                        ),
                    )
                except httpx.HTTPError as e:
                    logger.warning(
                        "verify_send_message_failed",
                        session=rec.session_id,
                        err=str(e),
                    )
                    self.store.log_event(
                        report.dedupe_key,
                        "verify_send_message_failed",
                        {"err": str(e), "session_id": rec.session_id},
                    )
