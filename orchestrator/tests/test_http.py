"""HTTP-level tests: exercise FastAPI endpoints via TestClient.

These run the full lifespan (DB init, DI wiring) so they catch wiring bugs
unit tests on individual classes cannot.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import reset_settings_for_test


@pytest.fixture
def client(monkeypatch) -> Iterator[TestClient]:
    """Spin up a TestClient against a throwaway SQLite DB in mock mode.

    Reimports app.main so the fresh settings pick up our monkeypatched env.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        db_path = tf.name
    monkeypatch.setenv("ORCHESTRATOR_DB_PATH", db_path)
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("INGEST_SHARED_SECRET", "test-secret")
    monkeypatch.setenv("MIN_SEVERITY", "HIGH")
    monkeypatch.setenv("MIN_CVSS", "7.0")
    reset_settings_for_test()

    # Import lazily so the lifespan sees our env.
    import importlib

    from app import main as app_main

    importlib.reload(app_main)

    with TestClient(app_main.app) as c:
        yield c

    os.unlink(db_path)
    reset_settings_for_test()


# --------------------------------------------------------------------------- #
# /healthz                                                                    #
# --------------------------------------------------------------------------- #


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "ts" in body


def test_root_redirects_to_dashboard(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/dashboard"


# --------------------------------------------------------------------------- #
# /stats and /dashboard                                                       #
# --------------------------------------------------------------------------- #


def test_stats_empty(client):
    r = client.get("/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["total_findings"] == 0
    assert body["active_sessions"] == 0


def test_dashboard_renders(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Vulnerability Remediation" in r.text or "Dashboard" in r.text


# --------------------------------------------------------------------------- #
# /ingest auth + happy-path                                                   #
# --------------------------------------------------------------------------- #


_DEP_PAYLOAD = {
    "source": "pytest",
    "findings": [
        {
            "kind": "dep_cve",
            "repo": "o/r",
            "rule_id": "CVE-TEST-0001",
            "title": "test",
            "severity": "HIGH",
            "cvss": 8.2,
            "package_ecosystem": "PyPI",
            "package_name": "flask",
            "installed_version": "2.3.3",
            "fixed_versions": ["2.3.4"],
            "manifest_path": "requirements/base.txt",
            "scanner": "pip-audit",
        }
    ],
}


def test_ingest_requires_shared_secret(client):
    r = client.post("/ingest", json=_DEP_PAYLOAD)
    assert r.status_code == 401


def test_ingest_dispatches_and_deduplicates(client):
    headers = {"X-Ingest-Secret": "test-secret"}

    # First submission: dispatches.
    r1 = client.post("/ingest", json=_DEP_PAYLOAD, headers=headers)
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1["received"] == 1
    assert len(body1["results"]) == 1
    assert body1["results"][0]["status"] == "dispatched"

    # Second submission: deduped (local SQLite hit).
    r2 = client.post("/ingest", json=_DEP_PAYLOAD, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["results"][0]["status"] == "deduped"

    # Stats reflect one record.
    s = client.get("/stats").json()
    assert s["total_findings"] == 1


def test_ingest_filters_low_severity(client):
    headers = {"X-Ingest-Secret": "test-secret"}
    payload = {
        "source": "pytest",
        "findings": [
            {
                "kind": "dep_cve",
                "repo": "o/r",
                "rule_id": "CVE-LOW",
                "title": "low sev",
                "severity": "LOW",
                "cvss": 2.0,
                "package_ecosystem": "PyPI",
                "package_name": "pkg",
                "installed_version": "1.0.0",
                "fixed_versions": ["1.0.1"],
                "manifest_path": "requirements/base.txt",
                "scanner": "pip-audit",
            }
        ],
    }
    r = client.post("/ingest", json=payload, headers=headers)
    assert r.status_code == 200
    assert r.json()["results"][0]["status"] == "filtered"


# --------------------------------------------------------------------------- #
# /verify/result round-trip                                                   #
# --------------------------------------------------------------------------- #


def test_verify_result_round_trip(client):
    headers = {"X-Ingest-Secret": "test-secret"}
    sast_payload = {
        "source": "pytest",
        "findings": [
            {
                "kind": "sast",
                "repo": "o/r",
                "rule_id": "B324",
                "title": "weak hash",
                "severity": "HIGH",
                "file_path": "pkg/util.py",
                "line": 73,
                "scanner": "bandit",
            }
        ],
    }
    r = client.post("/ingest", json=sast_payload, headers=headers)
    assert r.status_code == 200
    key = r.json()["results"][0]["dedupe_key"]

    r = client.post(
        "/verify/result",
        json={
            "dedupe_key": key,
            "pr_url": "https://github.com/o/r/pull/42",
            "outcome": "clean",
        },
        headers=headers,
    )
    assert r.status_code == 200

    s = client.get("/stats").json()
    assert s["verified_fixed"] == 1


def test_verify_result_requires_auth(client):
    r = client.post(
        "/verify/result",
        json={"dedupe_key": "x", "outcome": "clean"},
    )
    assert r.status_code == 401
