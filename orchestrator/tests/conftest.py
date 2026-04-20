"""Shared fixtures + helpers for the orchestrator test suite.

Keeps test scaffolding DRY: one place that builds a throwaway SQLite store,
fake mocked Devin/GitHub clients, and a minimal settings object.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

import pytest

from app.db import Store
from app.devin_client import DevinClient
from app.github_client import GitHubClient
from app.models import Finding, FindingKind, Severity


class FakeSettings:
    """Minimal settings object suitable for pipeline/verifier tests."""

    target_repo = "o/r"
    issue_label = "devin-remediation"
    target_base_branch = "main"
    dry_run = False
    mock_mode = True
    ingest_shared_secret = ""
    stale_pr_warn_hours = 24.0
    stale_pr_flag_hours = 48.0
    acu_usd_rate = 0.0
    baseline_hours_per_finding = 2.0


@pytest.fixture
def tmp_store() -> Iterator[Store]:
    """A Store backed by a temp SQLite file that's cleaned up after the test."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        path = tf.name
    store = Store(path)
    try:
        yield store
    finally:
        os.unlink(path)


@pytest.fixture
def fake_devin() -> DevinClient:
    return DevinClient(api_key="x", org_id="y", mock=True)


@pytest.fixture
def fake_gh() -> GitHubClient:
    return GitHubClient(token="x", mock=True)


def make_dep_finding(
    *,
    rule: str = "CVE-2025-0001",
    pkg: str = "flask",
    installed: str = "2.3.3",
    fixed: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    cvss: float | None = 8.0,
    repo: str = "o/r",
) -> Finding:
    return Finding(
        kind=FindingKind.DEP_CVE,
        repo=repo,
        rule_id=rule,
        title=f"{rule} in {pkg}",
        severity=severity,
        cvss=cvss,
        package_ecosystem="PyPI",
        package_name=pkg,
        installed_version=installed,
        fixed_versions=fixed if fixed is not None else ["2.3.4"],
        manifest_path="requirements/base.txt",
        scanner="pip-audit",
    )


def make_sast_finding(
    *,
    rule: str = "B324",
    file_path: str = "pkg/util.py",
    line: int = 73,
    severity: Severity = Severity.HIGH,
    repo: str = "o/r",
) -> Finding:
    return Finding(
        kind=FindingKind.SAST,
        repo=repo,
        rule_id=rule,
        title=f"{rule} at {file_path}",
        severity=severity,
        file_path=file_path,
        line=line,
        scanner="bandit",
    )
