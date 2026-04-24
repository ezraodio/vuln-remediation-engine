"""Tests for the stale-PR reconciler.

Exercises the four transitions `_reconcile_stale_pr` is responsible for:
merged → MERGED_UNVERIFIED, closed → HUMAN_REJECTED, open+aged →
NEEDS_ATTENTION, and the no-op case for PRs that are still fresh.
"""
from __future__ import annotations

from datetime import timedelta

from app.models import RemediationRecord, RemediationStatus, Severity
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc

from .conftest import FakeSettings, make_sast_finding


def _pipeline(store, devin, gh):
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    return RemediationPipeline(
        settings=FakeSettings(), store=store, devin=devin, gh=gh, router=router
    )


def _pr_opened_record(store, *, age_hours: float):
    f = make_sast_finding()
    now = now_utc()
    past = now - timedelta(hours=age_hours)
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        created_at=past,
        updated_at=past,
    )
    store.upsert(rec)
    return rec


async def _fake_active_session(*_a, **_kw):
    return {"session_id": "sess-1", "status": "running", "pull_requests": []}


async def test_merged_pr_transitions_to_merged_unverified(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    rec = _pr_opened_record(tmp_store, age_hours=30)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "closed", "merged": True}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.MERGED_UNVERIFIED
    assert out.resolved_at is not None


async def test_closed_without_merge_transitions_to_human_rejected(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    rec = _pr_opened_record(tmp_store, age_hours=30)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "closed", "merged": False}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.HUMAN_REJECTED
    assert out.resolved_at is not None


async def test_open_past_flag_threshold_transitions_to_needs_attention(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    rec = _pr_opened_record(tmp_store, age_hours=72)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "open", "merged": False}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.NEEDS_ATTENTION


async def test_needs_attention_pr_still_advances_on_merge(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """A record already flagged NEEDS_ATTENTION must still be re-polled.

    Regression: before, ``reconcile_session`` only invoked the stale-PR
    reconciler for status == PR_OPENED, so a PR that aged into
    NEEDS_ATTENTION and then got merged by a human would stay flagged forever.
    """
    f = make_sast_finding()
    now = now_utc()
    past = now - timedelta(hours=72)
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.NEEDS_ATTENTION,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        created_at=past,
        updated_at=past,
        pr_opened_at=past,
    )
    tmp_store.upsert(rec)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "closed", "merged": True}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.MERGED_UNVERIFIED
    assert out.resolved_at is not None


async def test_fresh_open_pr_stays_in_pr_opened(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    # Under the warn threshold — dashboard shouldn't flag it yet either.
    rec = _pr_opened_record(tmp_store, age_hours=1)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "open", "merged": False}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.PR_OPENED


async def test_verification_failed_pr_still_advances_on_merge(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """A VERIFICATION_FAILED record with a PR must still be reconciled.

    Regression: before, reconcile_session only routed PR_OPENED and
    NEEDS_ATTENTION records into ``_reconcile_stale_pr``. A finding whose
    verifier reported ``still_vulnerable`` but whose Devin session then ended
    would sit in VERIFICATION_FAILED forever, even if a human later merged
    or closed the PR.
    """
    f = make_sast_finding()
    now = now_utc()
    past = now - timedelta(hours=30)
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.VERIFICATION_FAILED,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        created_at=past,
        updated_at=past,
        pr_opened_at=past,
    )
    tmp_store.upsert(rec)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "closed", "merged": True}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.MERGED_UNVERIFIED
    assert out.resolved_at is not None


async def test_verification_failed_pr_ages_into_needs_attention(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """VERIFICATION_FAILED rows past the flag threshold must reach operators.

    Without the stale-PR reconciler handling this status, an aged failed
    verification would never surface on the needs-attention dashboard gate.
    """
    f = make_sast_finding()
    now = now_utc()
    past = now - timedelta(hours=72)
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.VERIFICATION_FAILED,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        created_at=past,
        updated_at=past,
        pr_opened_at=past,
    )
    tmp_store.upsert(rec)
    monkeypatch.setattr(fake_devin, "get_session", _fake_active_session)

    async def fake_state(url):  # noqa: ARG001
        return {"state": "open", "merged": False}

    monkeypatch.setattr(fake_gh, "get_pr_state", fake_state)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.NEEDS_ATTENTION
