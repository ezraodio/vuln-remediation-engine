"""Regression tests for bugs surfaced in the Round-7 interview-grade audit.

One test per invariant, named after the contract it pins down so a
regression points directly at the broken behaviour:

* ``test_dispatch_success_swallows_github_comment_error`` — the
  :robot: comment posted after a successful Devin dispatch is best-effort.
  SESSION_RUNNING is already persisted by the time we comment, so a
  GitHub flap must not 500 /ingest and provoke a scanner retry of work we
  already dispatched.

* ``test_pr_opened_swallows_github_comment_error`` — symmetry for the
  :sparkles: comment fired when reconcile transitions a record to
  PR_OPENED. PR_OPENED is already persisted, so a GitHub flap must not
  propagate through /reconcile and halt the sweep.

* ``test_reconcile_endpoint_tolerates_per_record_error`` — one record's
  unhandled error during /reconcile must not starve the remaining rows.
  Mirrors the per-finding isolation /ingest already has.
"""
from __future__ import annotations

import httpx

from app.main import app, reconcile
from app.models import (
    RemediationRecord,
    RemediationStatus,
    Severity,
)
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc

from .conftest import FakeSettings, make_dep_finding, make_sast_finding


def _pipeline(tmp_store, fake_devin, fake_gh):
    return RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=Router(min_severity=Severity.HIGH, min_cvss=7.0),
    )


async def test_dispatch_success_swallows_github_comment_error(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    async def boom_comment_issue(*_a, **_kw):
        raise httpx.ConnectError("github flap")

    monkeypatch.setattr(fake_gh, "comment_issue", boom_comment_issue)

    result = await _pipeline(tmp_store, fake_devin, fake_gh).handle_finding(
        make_dep_finding(), source="test"
    )

    assert result.status == RemediationStatus.DISPATCHED
    rec = tmp_store.get(result.dedupe_key)
    assert rec is not None
    assert rec.status == RemediationStatus.SESSION_RUNNING
    assert "devin_dispatched_comment_failed" in {
        e["kind"] for e in tmp_store.recent_events(limit=50)
    }


async def test_pr_opened_swallows_github_comment_error(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    f = make_sast_finding()
    now = now_utc()
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.SESSION_RUNNING,
        session_id="sess-1",
        issue_number=1,
        created_at=now,
        updated_at=now,
    )
    tmp_store.upsert(rec)

    async def fake_get_session(_sid):
        return {
            "session_id": "sess-1",
            "status": "finished",
            "pull_requests": [
                {"url": "https://github.com/o/r/pull/42", "html_url": "https://github.com/o/r/pull/42"}
            ],
        }

    async def boom_comment_issue(*_a, **_kw):
        raise httpx.ConnectError("github flap")

    monkeypatch.setattr(fake_devin, "get_session", fake_get_session)
    monkeypatch.setattr(fake_gh, "comment_issue", boom_comment_issue)

    await _pipeline(tmp_store, fake_devin, fake_gh).reconcile_session(rec)

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.PR_OPENED
    assert out.pr_url == "https://github.com/o/r/pull/42"
    assert "pr_opened_comment_failed" in {
        e["kind"] for e in tmp_store.recent_events(limit=50)
    }


async def test_reconcile_endpoint_tolerates_per_record_error(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """A single record raising inside reconcile_session must not halt the
    sweep. Two DISPATCHED rows: the first one's Devin call blows up, the
    second should still be reconciled (and end up PR_OPENED)."""
    bad_rec = RemediationRecord(
        dedupe_key="bad-rec",
        finding=make_sast_finding(rule="B324", file_path="a.py"),
        status=RemediationStatus.SESSION_RUNNING,
        session_id="sess-bad",
        issue_number=1,
        created_at=now_utc(),
        updated_at=now_utc(),
    )
    good_rec = RemediationRecord(
        dedupe_key="good-rec",
        finding=make_sast_finding(rule="B506", file_path="b.py"),
        status=RemediationStatus.SESSION_RUNNING,
        session_id="sess-good",
        issue_number=2,
        created_at=now_utc(),
        updated_at=now_utc(),
    )
    tmp_store.upsert(bad_rec)
    tmp_store.upsert(good_rec)

    async def get_session(sid):
        if sid == "sess-bad":
            raise RuntimeError("devin exploded on this one")
        return {
            "session_id": sid,
            "status": "finished",
            "pull_requests": [
                {"url": "https://github.com/o/r/pull/7", "html_url": "https://github.com/o/r/pull/7"}
            ],
        }

    monkeypatch.setattr(fake_devin, "get_session", get_session)

    app.state.settings = FakeSettings()
    app.state.store = tmp_store
    app.state.devin = fake_devin
    app.state.gh = fake_gh
    app.state.pipeline = _pipeline(tmp_store, fake_devin, fake_gh)

    result = await reconcile(x_ingest_secret=None)

    assert result["errored"] == 1
    assert result["reconciled"] == 1
    assert tmp_store.get("good-rec").status == RemediationStatus.PR_OPENED
    assert tmp_store.get("bad-rec").status == RemediationStatus.SESSION_RUNNING
