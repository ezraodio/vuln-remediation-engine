"""Regression tests for findings surfaced by Devin Review on PR #2.

Two distinct invariants, each pinned by a named test:

* ``test_acu_cost_histogram_observed_once_per_session*`` — the
  ``vrm_acu_cost_per_session`` histogram must get exactly one sample
  per session, taken at the terminal transition. Observing on every
  reconcile tick (as an earlier revision did) inflates the sample
  count and sum with the session's intermediate running totals
  (1, 2, 3, …, N) instead of a single sample of N, making percentile
  and average math misleading for cost alerting / budgeting dashboards.

* ``test_verified_fixed_closes_tracking_issue`` /
  ``test_verified_fixed_close_issue_error_is_best_effort`` — the
  README contract says CLEAN verification closes the tracking issue.
  Without the close call, operator tracking tabs accumulate resolved
  issues indefinitely; with it wired un-guarded, a GitHub flap on the
  close call would 500 /verify/result after the status is already
  persisted, provoking a CI retry of work we've recorded.
"""
from __future__ import annotations

import httpx
import pytest
from prometheus_client import REGISTRY

from app.models import RemediationRecord, RemediationStatus
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc
from app.verifier import Verifier, VerifyOutcome, VerifyReport

from .conftest import FakeSettings, make_dep_finding, make_sast_finding


def _acu_hist_snapshot() -> tuple[float, float]:
    """Return ``(sample_count, sample_sum)`` of the ACU-per-session histogram."""
    count = (
        REGISTRY.get_sample_value("vrm_acu_cost_per_session_count") or 0.0
    )
    total = (
        REGISTRY.get_sample_value("vrm_acu_cost_per_session_sum") or 0.0
    )
    return count, total


def _pipeline(tmp_store, fake_devin, fake_gh) -> RemediationPipeline:
    return RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=Router(min_severity=make_dep_finding().severity, min_cvss=7.0),
    )


async def test_acu_cost_histogram_observed_once_per_session_on_terminal_transition(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Five ticks of rising ACU + one terminal transition = ONE histogram sample."""
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

    pipeline = _pipeline(tmp_store, fake_devin, fake_gh)

    acu_trajectory = iter([1.0, 2.0, 3.0, 4.0, 5.0])

    async def fake_get_session(_sid):
        return {
            "session_id": "sess-1",
            "status": "running",
            "pull_requests": [],
            "acu_cost": next(acu_trajectory),
        }

    monkeypatch.setattr(fake_devin, "get_session", fake_get_session)

    before_count, before_sum = _acu_hist_snapshot()

    for _ in range(5):
        fresh = tmp_store.get(rec.dedupe_key)
        assert fresh is not None
        await pipeline.reconcile_session(fresh)

    mid_count, mid_sum = _acu_hist_snapshot()
    assert mid_count == before_count, (
        "Per-tick reconcile must NOT observe the histogram — running totals "
        "would stack into fake per-session samples."
    )
    assert mid_sum == before_sum

    async def fake_get_session_ended(_sid):
        return {
            "session_id": "sess-1",
            "status": "finished",
            "pull_requests": [],
            "acu_cost": 5.0,
        }

    monkeypatch.setattr(fake_devin, "get_session", fake_get_session_ended)
    fresh = tmp_store.get(rec.dedupe_key)
    assert fresh is not None
    await pipeline.reconcile_session(fresh)

    after_count, after_sum = _acu_hist_snapshot()
    assert after_count == before_count + 1, (
        "Exactly one sample must land when the session transitions to a "
        "terminal status (FAILED here)."
    )
    assert pytest.approx(after_sum - before_sum) == 5.0


async def test_acu_cost_histogram_observed_once_on_verified_fixed(
    tmp_store, fake_devin, fake_gh
):
    """CLEAN verification is the other terminal path and must observe too."""
    f = make_sast_finding(rule="B506", file_path="v.py")
    now = now_utc()
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-v",
        issue_number=7,
        pr_url="https://github.com/o/r/pull/9",
        acu_cost=3.5,
        created_at=now,
        updated_at=now,
    )
    tmp_store.upsert(rec)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    before_count, before_sum = _acu_hist_snapshot()

    await verifier.handle_report(
        VerifyReport(
            dedupe_key=rec.dedupe_key,
            pr_url=rec.pr_url,
            outcome=VerifyOutcome.CLEAN,
        )
    )

    after_count, after_sum = _acu_hist_snapshot()
    assert after_count == before_count + 1
    assert pytest.approx(after_sum - before_sum) == 3.5


async def test_verified_fixed_closes_tracking_issue(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """README contract: CLEAN outcome closes the tracking issue."""
    f = make_dep_finding()
    now = now_utc()
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-c",
        issue_number=42,
        pr_url="https://github.com/o/r/pull/3",
        created_at=now,
        updated_at=now,
    )
    tmp_store.upsert(rec)

    closed: list[tuple[str, int]] = []

    async def capture_close(repo, number, *, reason="completed"):
        closed.append((repo, number))

    monkeypatch.setattr(fake_gh, "close_issue", capture_close)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    await verifier.handle_report(
        VerifyReport(
            dedupe_key=rec.dedupe_key,
            pr_url=rec.pr_url,
            outcome=VerifyOutcome.CLEAN,
        )
    )

    assert closed == [("o/r", 42)]
    assert tmp_store.get(rec.dedupe_key).status == RemediationStatus.VERIFIED_FIXED


async def test_verified_fixed_close_issue_error_is_best_effort(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """A GitHub flap on close_issue must not propagate: VERIFIED_FIXED is
    already persisted. Propagating would 500 /verify/result and trip the
    scanner's CI retry into replaying the body — which the terminal-status
    guard would then rightly reject, but the 500 is still the wrong signal."""
    f = make_sast_finding(rule="B324", file_path="h.py")
    now = now_utc()
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-e",
        issue_number=8,
        pr_url="https://github.com/o/r/pull/4",
        created_at=now,
        updated_at=now,
    )
    tmp_store.upsert(rec)

    async def boom_close(*_a, **_kw):
        raise httpx.ConnectError("github flap")

    monkeypatch.setattr(fake_gh, "close_issue", boom_close)

    verifier = Verifier(store=tmp_store, devin=fake_devin, gh=fake_gh)
    await verifier.handle_report(
        VerifyReport(
            dedupe_key=rec.dedupe_key,
            pr_url=rec.pr_url,
            outcome=VerifyOutcome.CLEAN,
        )
    )

    out = tmp_store.get(rec.dedupe_key)
    assert out.status == RemediationStatus.VERIFIED_FIXED
    assert "verify_fixed_close_issue_failed" in {
        e["kind"] for e in tmp_store.recent_events(limit=50)
    }


async def test_close_issue_hits_patch_endpoint(respx_mock):
    """Contract test: close_issue PATCHes the issue with state=closed."""
    from app.github_client import GitHubClient

    route = respx_mock.patch(
        "https://api.github.com/repos/o/r/issues/11"
    ).respond(
        status_code=200,
        json={"number": 11, "state": "closed"},
    )
    gh = GitHubClient(token="t")
    await gh.close_issue("o/r", 11)
    assert route.called
    assert route.calls.last.request.content
