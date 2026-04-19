"""Tests for the SQLite Store: upsert, update_status, events, list_all."""
from __future__ import annotations

from app.models import RemediationRecord, RemediationStatus
from app.time_utils import now_utc

from .conftest import make_dep_finding


def _record(status: RemediationStatus = RemediationStatus.DISPATCHED) -> RemediationRecord:
    f = make_dep_finding()
    now = now_utc()
    return RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=status,
        created_at=now,
        updated_at=now,
    )


def test_upsert_then_get_roundtrip(tmp_store):
    rec = _record()
    tmp_store.upsert(rec)
    fetched = tmp_store.get(rec.dedupe_key)
    assert fetched is not None
    assert fetched.dedupe_key == rec.dedupe_key
    assert fetched.status == RemediationStatus.DISPATCHED
    assert fetched.finding.rule_id == rec.finding.rule_id


def test_get_missing_returns_none(tmp_store):
    assert tmp_store.get("does-not-exist") is None


def test_update_status_mutates_and_sets_resolved(tmp_store):
    rec = _record()
    tmp_store.upsert(rec)

    tmp_store.update_status(
        rec.dedupe_key,
        RemediationStatus.VERIFIED_FIXED,
        pr_url="https://example.com/pr/1",
        mark_resolved=True,
    )

    updated = tmp_store.get(rec.dedupe_key)
    assert updated is not None
    assert updated.status == RemediationStatus.VERIFIED_FIXED
    assert updated.pr_url == "https://example.com/pr/1"
    assert updated.resolved_at is not None


def test_update_status_without_resolved_does_not_touch_resolved_at(tmp_store):
    rec = _record()
    tmp_store.upsert(rec)
    tmp_store.update_status(rec.dedupe_key, RemediationStatus.SESSION_RUNNING)
    updated = tmp_store.get(rec.dedupe_key)
    assert updated is not None
    assert updated.resolved_at is None


def test_list_all_orders_newest_first(tmp_store):
    # Insert a few records with explicit timestamps.
    f1 = make_dep_finding(rule="CVE-A")
    f2 = make_dep_finding(rule="CVE-B")
    f3 = make_dep_finding(rule="CVE-C")
    t = now_utc()
    for i, f in enumerate([f1, f2, f3]):
        tmp_store.upsert(
            RemediationRecord(
                dedupe_key=f.dedupe_key() + str(i),
                finding=f,
                status=RemediationStatus.DISPATCHED,
                created_at=t.replace(microsecond=i * 1000),
                updated_at=t,
            )
        )
    rows = tmp_store.list_all()
    assert len(rows) == 3
    # Descending created_at → newest (i=2) first.
    assert rows[0].finding.rule_id == "CVE-C"


def test_log_event_and_recent_events(tmp_store):
    rec = _record()
    tmp_store.upsert(rec)
    tmp_store.log_event(rec.dedupe_key, "issue_created", {"url": "https://ex.com/1"})
    tmp_store.log_event(rec.dedupe_key, "devin_dispatched", {"session_id": "s-1"})

    events = tmp_store.recent_events(10)
    kinds = [e["kind"] for e in events]
    assert "issue_created" in kinds
    assert "devin_dispatched" in kinds
