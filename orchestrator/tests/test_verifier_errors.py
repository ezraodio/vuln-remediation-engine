"""Verifier must still transition state when send_message fails on an archived session."""
from __future__ import annotations

import httpx

from app.models import RemediationRecord, RemediationStatus
from app.time_utils import now_utc
from app.verifier import Verifier, VerifyOutcome, VerifyReport

from .conftest import make_sast_finding


def _rec(session_id: str | None = "sess-1") -> RemediationRecord:
    f = make_sast_finding()
    now = now_utc()
    return RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id=session_id,
        issue_number=1,
        pr_url="https://github.com/o/r/pull/1",
        created_at=now,
        updated_at=now,
    )


async def test_still_vuln_records_status_even_if_send_message_fails(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """send_message is best-effort; its failure must not crash /verify/result.

    The session may be archived or Devin may be unreachable. The *verification
    result* itself has already been recorded in our store before send_message
    fires, so the HTTP endpoint must return 200 and surface the failure
    through logs/events rather than propagating a 5xx to the scanner
    workflow (which would retry a fix-loop we already processed).
    """
    rec = _rec()
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise httpx.HTTPStatusError(
            "410",
            request=httpx.Request("POST", "http://x"),
            response=httpx.Response(410),
        )

    monkeypatch.setattr(fake_devin, "send_message", boom)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    report = VerifyReport(
        dedupe_key=rec.dedupe_key,
        pr_url=rec.pr_url,
        outcome=VerifyOutcome.STILL_VULNERABLE,
        scanner_output="bandit: still there",
    )

    await verifier.handle_report(report)

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.VERIFICATION_FAILED
    assert out.pr_url == rec.pr_url

    events = tmp_store.recent_events(limit=50)
    kinds = {e["kind"] for e in events}
    assert "verify_report" in kinds
    assert "verify_send_message_failed" in kinds


async def test_clean_outcome_swallows_gh_comment_errors(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Clean-outcome path must not 500 /verify/result on a GitHub flap.

    VERIFIED_FIXED is already persisted before the comment fires. Letting
    the comment error propagate would 500 the scanner's CI POST and provoke
    a retry that — without a terminal-status guard — would double-count
    MTTR and verify_outcomes. The fix is a best-effort comment: log the
    failure through the audit log so operators can still trace it, but the
    endpoint stays 2xx because the work behind it has already succeeded.
    """
    rec = _rec()
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise httpx.ConnectError("gh unreachable")

    monkeypatch.setattr(fake_gh, "comment_issue", boom)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    report = VerifyReport(
        dedupe_key=rec.dedupe_key,
        pr_url=rec.pr_url,
        outcome=VerifyOutcome.CLEAN,
    )

    await verifier.handle_report(report)

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.VERIFIED_FIXED
    assert out.resolved_at is not None
    events = tmp_store.recent_events(limit=50)
    assert "verify_fixed_comment_failed" in {e["kind"] for e in events}


async def test_still_vuln_swallows_gh_comment_errors(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Symmetry with the CLEAN path: a comment failure on STILL_VULN must
    not 500 the verify endpoint either, since VERIFICATION_FAILED is
    already persisted by the time we comment."""
    rec = _rec()
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise httpx.ConnectError("gh unreachable")

    monkeypatch.setattr(fake_gh, "comment_issue", boom)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    report = VerifyReport(
        dedupe_key=rec.dedupe_key,
        pr_url=rec.pr_url,
        outcome=VerifyOutcome.STILL_VULNERABLE,
        scanner_output="bandit: still there",
    )

    await verifier.handle_report(report)

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.VERIFICATION_FAILED
    events = tmp_store.recent_events(limit=50)
    assert "verify_failed_comment_failed" in {e["kind"] for e in events}


async def test_verify_report_is_idempotent_on_terminal_status(
    tmp_store, fake_devin, fake_gh
):
    """CI retries of /verify/result for a record already in a terminal
    status (e.g. because the first call succeeded but the response was lost)
    must be no-ops. Re-entering the body would double-observe MTTR,
    re-increment verify_outcomes, and log a duplicate verify_report event."""
    rec = _rec()
    rec.status = RemediationStatus.VERIFIED_FIXED
    tmp_store.upsert(rec)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    report = VerifyReport(
        dedupe_key=rec.dedupe_key,
        pr_url=rec.pr_url,
        outcome=VerifyOutcome.CLEAN,
    )

    await verifier.handle_report(report)
    await verifier.handle_report(report)

    events = tmp_store.recent_events(limit=50)
    assert [e["kind"] for e in events].count("verify_report") == 0
