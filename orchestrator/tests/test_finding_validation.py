"""Input-validation coverage for the Finding schema.

The /ingest boundary is the only place untrusted scanner output enters
the system. These tests pin down what we accept and what we reject, so
malformed output never silently creates a broken RemediationRecord or a
confusing KeyError halfway through the pipeline.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import Finding, FindingKind, Severity


def _dep_base() -> dict:
    return {
        "kind": "dep_cve",
        "repo": "o/r",
        "rule_id": "CVE-1",
        "title": "t",
        "severity": "HIGH",
        "cvss": 8.0,
        "package_ecosystem": "PyPI",
        "package_name": "flask",
        "installed_version": "2.3.3",
        "fixed_versions": ["2.3.4"],
        "manifest_path": "requirements/base.txt",
        "scanner": "pip-audit",
    }


def _sast_base() -> dict:
    return {
        "kind": "sast",
        "repo": "o/r",
        "rule_id": "B324",
        "title": "weak hash",
        "severity": "HIGH",
        "file_path": "pkg/u.py",
        "line": 12,
        "scanner": "bandit",
    }


# ---------------- happy paths ----------------


def test_dep_cve_happy_path():
    f = Finding.model_validate(_dep_base())
    assert f.kind == FindingKind.DEP_CVE
    assert f.severity == Severity.HIGH


def test_sast_happy_path():
    f = Finding.model_validate(_sast_base())
    assert f.kind == FindingKind.SAST
    assert f.file_path == "pkg/u.py"


# ---------------- repo ----------------


@pytest.mark.parametrize("repo", ["", "owner", "owner/", "/repo", "a/b/c"])
def test_repo_must_be_owner_slash_name(repo):
    payload = _dep_base() | {"repo": repo}
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


# ---------------- cvss ----------------


@pytest.mark.parametrize("cvss", [-0.1, 10.1, 100.0])
def test_cvss_out_of_range_rejected(cvss):
    payload = _dep_base() | {"cvss": cvss}
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


def test_cvss_none_allowed():
    payload = _dep_base() | {"cvss": None}
    f = Finding.model_validate(payload)
    assert f.cvss is None


# ---------------- line ----------------


def test_line_must_be_positive():
    payload = _sast_base() | {"line": 0}
    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


# ---------------- kind-specific required fields ----------------


@pytest.mark.parametrize(
    "missing_field",
    ["package_name", "installed_version", "manifest_path"],
)
def test_dep_cve_rejects_missing_required_field(missing_field):
    payload = _dep_base()
    payload[missing_field] = None
    with pytest.raises(ValidationError) as ei:
        Finding.model_validate(payload)
    assert missing_field in str(ei.value)


def test_sast_rejects_missing_file_path():
    payload = _sast_base()
    payload["file_path"] = None
    with pytest.raises(ValidationError) as ei:
        Finding.model_validate(payload)
    assert "file_path" in str(ei.value)
