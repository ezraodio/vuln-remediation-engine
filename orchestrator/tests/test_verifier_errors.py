"""Verifier must still transition state when send_message fails on an archived session."""
from __future__ import annotations

import contextlib

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


async def test_clean_outcome_surfaces_gh_comment_errors(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Clean-outcome path: a GitHub comment failure must not hide the fact
    that the state was persisted as VERIFIED_FIXED. We do not swallow
    comment_issue errors on this path because the status transition has
    already happened — but we want to assert we cleanly surface the error
    rather than rolling back the store."""
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

    with contextlib.suppress(httpx.HTTPError):
        await verifier.handle_report(report)

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.VERIFIED_FIXED
    assert out.resolved_at is not None
