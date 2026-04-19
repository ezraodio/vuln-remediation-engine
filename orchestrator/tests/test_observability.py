"""Tests for observability.compute_stats — counters, MTTR, success rate."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.models import RemediationRecord, RemediationStatus
from app.observability import _percentile, compute_stats
from app.time_utils import now_utc

from .conftest import make_dep_finding, make_sast_finding


def _rec(
    *,
    status: RemediationStatus,
    created_ago_s: float = 0,
    resolved_ago_s: float | None = None,
    finding=None,
    pr_url: str | None = None,
    key_suffix: str = "",
) -> RemediationRecord:
    """Build a RemediationRecord with relative timestamps for MTTR tests."""
    finding = finding or make_dep_finding(rule=f"CVE-{key_suffix or 'x'}")
    now = now_utc()
    created_at = now - timedelta(seconds=created_ago_s)
    resolved_at = (
        now - timedelta(seconds=resolved_ago_s) if resolved_ago_s is not None else None
    )
    return RemediationRecord(
        dedupe_key=finding.dedupe_key() + key_suffix,
        finding=finding,
        status=status,
        pr_url=pr_url,
        created_at=created_at,
        updated_at=now,
        resolved_at=resolved_at,
    )


def _insert(store, records: list[RemediationRecord]) -> None:
    for r in records:
        store.upsert(r)


def test_percentile_basic():
    # Linear-interpolation percentile matches numpy's default (method="linear").
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert _percentile(data, 0.0) == 10.0
    assert _percentile(data, 1.0) == 50.0
    assert _percentile(data, 0.5) == 30.0
    # p=0.9 over 5 points → index 3.6 → 40 + 0.6*(50-40) = 46.0
    assert _percentile(data, 0.9) == pytest.approx(46.0)


def test_percentile_empty_list():
    assert _percentile([], 0.5) == 0.0


def test_compute_stats_counts_and_buckets(tmp_store):
    records = [
        _rec(status=RemediationStatus.DEDUPED, key_suffix="a"),
        _rec(
            status=RemediationStatus.SESSION_RUNNING,
            key_suffix="b",
            finding=make_sast_finding(rule="B101"),
        ),
        _rec(status=RemediationStatus.DISPATCHED, key_suffix="c"),
        _rec(
            status=RemediationStatus.PR_OPENED,
            key_suffix="d",
            pr_url="https://example.com/pr/1",
        ),
        _rec(
            status=RemediationStatus.VERIFIED_FIXED,
            key_suffix="e",
            created_ago_s=1200,
            resolved_ago_s=0,
            pr_url="https://example.com/pr/2",
        ),
        _rec(status=RemediationStatus.VERIFICATION_FAILED, key_suffix="f"),
        _rec(status=RemediationStatus.FILTERED, key_suffix="g"),
    ]
    _insert(tmp_store, records)

    s = compute_stats(tmp_store)

    assert s.total_findings == 7
    assert s.dedupe_hits == 1
    assert s.active_sessions == 2  # DISPATCHED + SESSION_RUNNING
    assert s.prs_opened == 2       # both records with pr_url populated
    assert s.verified_fixed == 1
    assert s.verification_failed == 1
    # by_status exposes every status bucket we observed.
    assert s.by_status["deduped"] == 1
    assert s.by_status["session_running"] == 1
    assert s.by_status["verified_fixed"] == 1
    assert s.by_status["filtered"] == 1


def test_compute_stats_mttr_percentiles(tmp_store):
    # Build three resolved records with clean 100s / 200s / 300s durations.
    records = [
        _rec(
            status=RemediationStatus.VERIFIED_FIXED,
            created_ago_s=100,
            resolved_ago_s=0,
            key_suffix="one",
        ),
        _rec(
            status=RemediationStatus.VERIFIED_FIXED,
            created_ago_s=200,
            resolved_ago_s=0,
            key_suffix="two",
        ),
        _rec(
            status=RemediationStatus.VERIFIED_FIXED,
            created_ago_s=300,
            resolved_ago_s=0,
            key_suffix="three",
        ),
    ]
    _insert(tmp_store, records)

    s = compute_stats(tmp_store)
    assert s.median_mttr_seconds == pytest.approx(200.0, abs=1.0)
    # p90 over [100,200,300] → 280 via linear interpolation.
    assert s.p90_mttr_seconds == pytest.approx(280.0, abs=1.0)


def test_success_rate_math(tmp_store):
    records = [
        _rec(status=RemediationStatus.VERIFIED_FIXED, key_suffix="ok1"),
        _rec(status=RemediationStatus.RESOLVED, key_suffix="ok2"),
        _rec(status=RemediationStatus.VERIFICATION_FAILED, key_suffix="fail1"),
        _rec(status=RemediationStatus.FAILED, key_suffix="fail2"),
    ]
    _insert(tmp_store, records)

    s = compute_stats(tmp_store)
    # 2 successes / (2 successes + 2 failures) = 0.5
    assert s.success_rate == pytest.approx(0.5)


def test_success_rate_none_when_no_terminal(tmp_store):
    _insert(
        tmp_store,
        [_rec(status=RemediationStatus.SESSION_RUNNING, key_suffix="run1")],
    )
    s = compute_stats(tmp_store)
    assert s.success_rate is None
    assert s.median_mttr_seconds is None
    assert s.p90_mttr_seconds is None


def test_empty_store_returns_zero_stats(tmp_store):
    s = compute_stats(tmp_store)
    assert s.total_findings == 0
    assert s.active_sessions == 0
    assert s.success_rate is None
    assert s.by_status == {}
    assert s.by_severity == {}
