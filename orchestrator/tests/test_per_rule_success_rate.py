"""Tests for the per-rule success-rate heatmap aggregation."""
from __future__ import annotations

from datetime import timedelta

from app.models import RemediationRecord, RemediationStatus
from app.observability import _compute_by_rule, compute_stats
from app.time_utils import now_utc

from .conftest import FakeSettings, make_sast_finding


def _rec(rule, status, *, acu=None, mttr_seconds=None):
    f = make_sast_finding(rule=rule, file_path=f"pkg/{rule}.py")
    now = now_utc()
    resolved = now + timedelta(seconds=mttr_seconds) if mttr_seconds else None
    return RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=status,
        acu_cost=acu,
        created_at=now,
        updated_at=now,
        resolved_at=resolved,
    )


def test_compute_by_rule_groups_by_rule_id():
    rows = [
        _rec("B324", RemediationStatus.VERIFIED_FIXED, acu=1.0, mttr_seconds=600),
        _rec("B324", RemediationStatus.VERIFIED_FIXED, acu=2.0, mttr_seconds=1200),
        _rec("B506", RemediationStatus.FAILED),
    ]
    # Override dedupe keys so two B324 records coexist.
    for i, r in enumerate(rows):
        r.dedupe_key = f"key-{i}"

    out = {rp.rule_id: rp for rp in _compute_by_rule(rows)}
    assert out["B324"].total == 2
    assert out["B324"].verified_fixed == 2
    assert out["B324"].success_rate == 1.0
    assert out["B324"].avg_acu_cost == 1.5
    assert out["B324"].median_mttr_seconds == 900
    assert out["B506"].success_rate == 0.0
    assert out["B506"].failed == 1


def test_compute_by_rule_sorts_highest_volume_first():
    rows = [
        _rec("BIG", RemediationStatus.VERIFIED_FIXED),
        _rec("BIG", RemediationStatus.VERIFIED_FIXED),
        _rec("SMALL", RemediationStatus.VERIFIED_FIXED),
    ]
    for i, r in enumerate(rows):
        r.dedupe_key = f"k-{i}"
    out = _compute_by_rule(rows)
    assert [rp.rule_id for rp in out] == ["BIG", "SMALL"]


def test_compute_by_rule_ties_break_by_success_rate_ascending():
    # Both rules have 1 row; the struggling one should float to the top.
    rows = [
        _rec("GOOD", RemediationStatus.VERIFIED_FIXED),
        _rec("BAD", RemediationStatus.FAILED),
    ]
    for i, r in enumerate(rows):
        r.dedupe_key = f"k-{i}"
    out = _compute_by_rule(rows)
    assert [rp.rule_id for rp in out] == ["BAD", "GOOD"]


def test_compute_by_rule_none_success_rate_when_only_in_flight():
    rows = [_rec("X", RemediationStatus.SESSION_RUNNING)]
    rows[0].dedupe_key = "k-0"
    out = _compute_by_rule(rows)
    assert out[0].success_rate is None
    assert out[0].in_flight == 1


def test_compute_stats_exposes_by_rule(tmp_store):
    now = now_utc()
    f1 = make_sast_finding(rule="B324", file_path="a.py")
    tmp_store.upsert(
        RemediationRecord(
            dedupe_key=f1.dedupe_key(),
            finding=f1,
            status=RemediationStatus.VERIFIED_FIXED,
            created_at=now,
            updated_at=now,
            resolved_at=now,
        )
    )
    stats = compute_stats(tmp_store, FakeSettings())
    assert len(stats.by_rule) == 1
    assert stats.by_rule[0].rule_id == "B324"
