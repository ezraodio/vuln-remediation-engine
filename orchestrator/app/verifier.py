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

from .db import Store
from .devin_client import DevinClient
from .github_client import GitHubClient
from .logging_config import get_logger
from .models import RemediationStatus

log = get_logger("verifier")


class VerifyOutcome(StrEnum):
    CLEAN = "clean"                 # finding no longer reported
    STILL_VULNERABLE = "still_vuln" # finding still present on branch
    UNKNOWN = "unknown"              # scanner error


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
        logger.info("verify_report_received")
        self.store.log_event(
            report.dedupe_key,
            "verify_report",
            {"outcome": report.outcome.value, "pr": report.pr_url},
        )

        if report.outcome == VerifyOutcome.CLEAN:
            self.store.update_status(
                report.dedupe_key,
                RemediationStatus.VERIFIED_FIXED,
                pr_url=report.pr_url,
                mark_resolved=True,
            )
            if rec.issue_number:
                await self.gh.comment_issue(
                    rec.finding.repo,
                    rec.issue_number,
                    f":white_check_mark: Verified fix on {report.pr_url}: "
                    f"`{rec.finding.rule_id}` no longer reported by the scanner.",
                )
            return

        if report.outcome == VerifyOutcome.STILL_VULNERABLE:
            self.store.update_status(
                report.dedupe_key,
                RemediationStatus.VERIFICATION_FAILED,
                pr_url=report.pr_url,
            )
            if rec.issue_number:
                await self.gh.comment_issue(
                    rec.finding.repo,
                    rec.issue_number,
                    f":x: Verification failed on {report.pr_url}: "
                    f"`{rec.finding.rule_id}` is still reported on your branch. "
                    f"Messaging the session to iterate.",
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
            return

        logger.warning("verify_report_unknown_outcome")
