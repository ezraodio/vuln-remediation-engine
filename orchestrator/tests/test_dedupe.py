"""End-to-end dedupe test using mock clients."""
from __future__ import annotations

import os
import tempfile

import pytest

from app.config import reset_settings_for_test
from app.db import Store
from app.devin_client import DevinClient
from app.github_client import GitHubClient
from app.models import Finding, FindingKind, Severity
from app.pipeline import RemediationPipeline
from app.router import Router


class _FakeSettings:
    target_repo = "o/r"
    issue_label = "devin-remediation"
    target_base_branch = "main"
    dry_run = False
    mock_mode = True


@pytest.fixture
def pipeline(monkeypatch):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        tmpdb = tf.name
    monkeypatch.setenv("ORCHESTRATOR_DB_PATH", tmpdb)
    reset_settings_for_test()
    store = Store(tmpdb)
    devin = DevinClient(api_key="x", org_id="y", mock=True)
    gh = GitHubClient(token="x", mock=True)
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="dispatch")
    p = RemediationPipeline(
        settings=_FakeSettings(), store=store, devin=devin, gh=gh, router=router
    )
    yield p
    os.unlink(tmpdb)


def _finding(rule="CVE-2025-0001"):
    return Finding(
        kind=FindingKind.DEP_CVE,
        repo="o/r",
        rule_id=rule,
        title="x",
        severity=Severity.HIGH,
        cvss=8.0,
        package_ecosystem="PyPI",
        package_name="flask",
        installed_version="2.3.3",
        fixed_versions=["2.3.4"],
        manifest_path="requirements/base.txt",
        scanner="pip-audit",
    )


async def test_dedupe_on_second_submit(pipeline):
    r1 = await pipeline.handle_finding(_finding(), source="test")
    assert r1.status.value == "dispatched"
    r2 = await pipeline.handle_finding(_finding(), source="test")
    assert r2.status.value == "deduped"
    assert r2.reason is not None


async def test_different_rule_is_not_deduped(pipeline):
    await pipeline.handle_finding(_finding(rule="CVE-1"), source="test")
    r = await pipeline.handle_finding(_finding(rule="CVE-2"), source="test")
    assert r.status.value == "dispatched"


async def test_severity_filter(pipeline):
    f = _finding()
    f.severity = Severity.LOW
    f.cvss = 2.0
    r = await pipeline.handle_finding(f, source="test")
    assert r.status.value == "filtered"
