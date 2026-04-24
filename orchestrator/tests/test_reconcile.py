"""Tests for RemediationPipeline.reconcile_session."""
from __future__ import annotations

import httpx

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


def _rec(status: RemediationStatus, *, session_id: str | None = "sess-1", pr_url: str | None = None):
    f = make_sast_finding()
    now = now_utc()
    return RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=status,
        session_id=session_id,
        pr_url=pr_url,
        issue_number=1,
        created_at=now,
        updated_at=now,
    )


async def test_reconcile_no_session_id_noop(tmp_store, fake_devin, fake_gh):
    rec = _rec(RemediationStatus.DISPATCHED, session_id=None)
    tmp_store.upsert(rec)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.DISPATCHED


async def test_reconcile_bails_on_terminal_status(tmp_store, fake_devin, fake_gh, monkeypatch):
    rec = _rec(RemediationStatus.VERIFIED_FIXED, pr_url="https://example.com/pr/1")
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise AssertionError("reconcile must not call Devin on terminal records")

    monkeypatch.setattr(fake_devin, "get_session", boom)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.VERIFIED_FIXED


async def test_reconcile_records_pr_when_devin_links_one(tmp_store, fake_devin, fake_gh, monkeypatch):
    rec = _rec(RemediationStatus.DISPATCHED)
    tmp_store.upsert(rec)

    async def fake_get(session_id):
        return {
            "session_id": session_id,
            "status": "blocked",
            "pull_requests": [{"url": "https://github.com/o/r/pull/42"}],
        }

    monkeypatch.setattr(fake_devin, "get_session", fake_get)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.PR_OPENED
    assert out.pr_url == "https://github.com/o/r/pull/42"


async def test_reconcile_marks_failed_when_session_inactive_and_no_pr(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    rec = _rec(RemediationStatus.DISPATCHED)
    tmp_store.upsert(rec)

    async def fake_get(session_id):
        return {"session_id": session_id, "status": "stopped", "pull_requests": []}

    monkeypatch.setattr(fake_devin, "get_session", fake_get)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.FAILED


async def test_reconcile_does_not_overwrite_pr_opened_without_prs_in_response(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    rec = _rec(RemediationStatus.PR_OPENED, pr_url="https://example.com/pr/1")
    tmp_store.upsert(rec)

    async def fake_get(session_id):
        return {"session_id": session_id, "status": "stopped", "pull_requests": []}

    monkeypatch.setattr(fake_devin, "get_session", fake_get)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.PR_OPENED


async def test_reconcile_swallows_http_errors(tmp_store, fake_devin, fake_gh, monkeypatch):
    rec = _rec(RemediationStatus.DISPATCHED)
    tmp_store.upsert(rec)

    async def boom(*_a, **_kw):
        raise httpx.ConnectError("devin unreachable")

    monkeypatch.setattr(fake_devin, "get_session", boom)
    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.DISPATCHED
