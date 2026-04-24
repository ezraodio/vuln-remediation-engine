"""/reconcile endpoint: only non-terminal records should be polled.

Regression net for: the cron-driven reconcile loop was previously using
`not rec.resolved_at` as the skip predicate, which let FAILED / FILTERED /
DEDUPED records trigger redundant Devin API calls on every tick.
"""
from __future__ import annotations

import importlib
import os
import tempfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import reset_settings_for_test
from app.models import RemediationRecord, RemediationStatus
from app.time_utils import now_utc

from .conftest import make_dep_finding


@pytest.fixture
def client(monkeypatch) -> Iterator[tuple[TestClient, object]]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        db_path = tf.name
    monkeypatch.setenv("ORCHESTRATOR_DB_PATH", db_path)
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("INGEST_SHARED_SECRET", "test-secret")
    monkeypatch.setenv("MIN_SEVERITY", "HIGH")
    monkeypatch.setenv("MIN_CVSS", "7.0")
    reset_settings_for_test()

    from app import main as app_main

    importlib.reload(app_main)
    with TestClient(app_main.app) as c:
        yield c, app_main
    os.unlink(db_path)
    reset_settings_for_test()


def _rec(status: RemediationStatus, *, session_id: str | None) -> RemediationRecord:
    f = make_dep_finding(rule=f"CVE-{status.value}")
    now = now_utc()
    return RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=status,
        session_id=session_id,
        issue_number=1,
        created_at=now,
        updated_at=now,
    )


def test_reconcile_skips_terminal_and_records_without_session(client, monkeypatch):
    c, app_main = client

    store = app_main.app.state.store
    pipeline = app_main.app.state.pipeline

    store.upsert(_rec(RemediationStatus.DISPATCHED, session_id="sess-live"))
    store.upsert(_rec(RemediationStatus.SESSION_RUNNING, session_id="sess-running"))
    store.upsert(_rec(RemediationStatus.FAILED, session_id="sess-dead"))
    store.upsert(_rec(RemediationStatus.VERIFIED_FIXED, session_id="sess-done"))
    store.upsert(_rec(RemediationStatus.FILTERED, session_id=None))
    store.upsert(_rec(RemediationStatus.DEDUPED, session_id=None))

    reconciled_ids: list[str] = []

    async def fake_reconcile(rec):
        reconciled_ids.append(rec.session_id)

    monkeypatch.setattr(pipeline, "reconcile_session", fake_reconcile)

    r = c.post("/reconcile", headers={"X-Ingest-Secret": "test-secret"})
    assert r.status_code == 200
    body = r.json()
    assert body["reconciled"] == 2
    assert body["skipped"] == 4
    assert sorted(reconciled_ids) == ["sess-live", "sess-running"]
