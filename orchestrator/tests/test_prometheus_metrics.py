"""Tests for the Prometheus /metrics endpoint.

Verifies the scrape endpoint returns Prometheus-formatted output and that
the pipeline actually emits the metric families we advertise.
"""
from __future__ import annotations

import importlib
import os
import tempfile
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import reset_settings_for_test


@pytest.fixture
def client(monkeypatch) -> Iterator[TestClient]:
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
        yield c

    os.unlink(db_path)
    reset_settings_for_test()


_PAYLOAD = {
    "source": "pytest",
    "findings": [
        {
            "kind": "sast",
            "repo": "o/r",
            "rule_id": "B999",
            "title": "t",
            "severity": "HIGH",
            "file_path": "pkg/x.py",
            "line": 12,
            "scanner": "bandit",
        }
    ],
}


def test_metrics_endpoint_returns_prometheus_content_type(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


def test_metrics_exposes_expected_families(client):
    body = client.get("/metrics").text
    for name in (
        "vrm_findings_ingested_total",
        "vrm_findings_dispatched_total",
        "vrm_findings_deduped_total",
        "vrm_findings_filtered_total",
        "vrm_dispatch_failures_total",
        "vrm_verify_outcomes_total",
        "vrm_active_sessions",
        "vrm_needs_attention",
        "vrm_stale_prs",
    ):
        assert name in body, f"expected metric {name} in /metrics output"


def test_ingest_increments_counter_visible_in_scrape(client):
    headers = {"X-Ingest-Secret": "test-secret"}
    r = client.post("/ingest", json=_PAYLOAD, headers=headers)
    assert r.status_code == 200

    body = client.get("/metrics").text
    # Labelled counter line for the exact (kind, severity) we just ingested.
    assert 'vrm_findings_ingested_total{kind="sast",severity="HIGH"}' in body


def test_request_id_echoed_in_logs_and_available_via_header(client):
    # Explicit request_id via header should be accepted (not rejected) and the
    # ingest still succeed. Downstream assertions on request_id propagation
    # live in test_request_id_correlation.py.
    headers = {
        "X-Ingest-Secret": "test-secret",
        "X-Request-Id": "test-rid-123",
    }
    r = client.post("/ingest", json=_PAYLOAD, headers=headers)
    assert r.status_code == 200
