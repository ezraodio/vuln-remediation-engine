"""Verifier must still transition state when send_message fails on an archived session."""
from __future__ import annotations

import httpx
import pytest

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
    rec = _rec()
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise httpx.HTTPStatusError(
            "410", request=httpx.Request("POST", "http://x"), response=httpx.Response(410)
        )

    monkeypatch.setattr(fake_devin, "send_message", boom)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    report = VerifyReport(
        dedupe_key=rec.dedupe_key,
        pr_url=rec.pr_url,
        outcome=VerifyOutcome.STILL_VULNERABLE,
        scanner_output="bandit: still there",
    )

    # Must not raise — session might be archived, but orchestrator must still
    # record the verification failure so dashboards/stats are truthful.
    with pytest.raises(httpx.HTTPError):
        await verifier.handle_report(report)

    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.VERIFICATION_FAILED
