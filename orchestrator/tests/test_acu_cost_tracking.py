"""Tests for ACU cost tracking — end-to-end from Devin session payload to
dashboard stats.
"""
from __future__ import annotations

from app.devin_client import DevinClient
from app.models import RemediationRecord, RemediationStatus, Severity
from app.observability import compute_stats
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc

from .conftest import FakeSettings, make_sast_finding


def test_session_acu_cost_extracts_canonical_field():
    assert DevinClient.session_acu_cost({"acu_cost": 1.25}) == 1.25


def test_session_acu_cost_falls_back_on_alternate_field_names():
    # Tolerate upstream API renames so cost dashboards don't silently zero out.
    assert DevinClient.session_acu_cost({"total_acus": 2.5}) == 2.5
    assert DevinClient.session_acu_cost({"acus_consumed": 3}) == 3.0
    assert DevinClient.session_acu_cost({"acus": 4}) == 4.0


def test_session_acu_cost_returns_none_when_absent():
    assert DevinClient.session_acu_cost({"status": "running"}) is None


async def test_reconcile_persists_acu_cost_from_session(
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

    async def fake_get(_session_id):
        return {
            "session_id": "sess-1",
            "status": "running",
            "pull_requests": [],
            "acu_cost": 3.75,
        }

    monkeypatch.setattr(fake_devin, "get_session", fake_get)
    pipeline = RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=Router(min_severity=Severity.HIGH, min_cvss=7.0),
    )

    await pipeline.reconcile_session(rec)
    assert tmp_store.get(rec.dedupe_key).acu_cost == 3.75


def test_compute_stats_rolls_up_cost_and_hours_saved(tmp_store):
    # One fixed finding at 2 ACUs, one filtered (counts for hours-saved, not cost).
    now = now_utc()
    f1 = make_sast_finding(rule="B324")
    f2 = make_sast_finding(rule="B506", file_path="pkg/other.py")
    tmp_store.upsert(
        RemediationRecord(
            dedupe_key=f1.dedupe_key(),
            finding=f1,
            status=RemediationStatus.VERIFIED_FIXED,
            acu_cost=2.0,
            created_at=now,
            updated_at=now,
            resolved_at=now,
        )
    )
    tmp_store.upsert(
        RemediationRecord(
            dedupe_key=f2.dedupe_key(),
            finding=f2,
            status=RemediationStatus.FILTERED,
            created_at=now,
            updated_at=now,
        )
    )

    class S(FakeSettings):
        acu_usd_rate = 2.5  # $2.50 per ACU
        baseline_hours_per_finding = 3.0

    stats = compute_stats(tmp_store, S())
    assert stats.total_acus_spent == 2.0
    assert stats.acu_per_fix == 2.0
    assert stats.total_usd_spent == 5.0
    assert stats.usd_per_fix == 5.0
    # Both triaged (VERIFIED_FIXED + FILTERED) count toward hours saved.
    assert stats.hours_saved_estimate == 6.0


def test_compute_stats_omits_usd_when_rate_unset(tmp_store):
    f = make_sast_finding()
    now = now_utc()
    tmp_store.upsert(
        RemediationRecord(
            dedupe_key=f.dedupe_key(),
            finding=f,
            status=RemediationStatus.VERIFIED_FIXED,
            acu_cost=1.0,
            created_at=now,
            updated_at=now,
            resolved_at=now,
        )
    )
    stats = compute_stats(tmp_store, FakeSettings())
    assert stats.total_usd_spent is None
    assert stats.usd_per_fix is None
