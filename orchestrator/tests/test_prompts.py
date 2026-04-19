from app.models import Finding, FindingKind, Severity
from app.prompts import build_prompt


def test_dep_prompt_contains_all_critical_fields():
    f = Finding(
        kind=FindingKind.DEP_CVE,
        repo="o/r",
        rule_id="CVE-2025-1234",
        title="t",
        severity=Severity.HIGH,
        cvss=8.8,
        package_ecosystem="PyPI",
        package_name="requests",
        installed_version="2.30.0",
        fixed_versions=["2.32.0"],
        manifest_path="requirements/base.txt",
        advisory_url="https://nvd.example/CVE-2025-1234",
        description="something bad",
        scanner="pip-audit",
    )
    p = build_prompt(f, target_repo="o/r", issue_number=42)
    assert "CVE-2025-1234" in p
    assert "requests" in p
    assert "2.30.0" in p
    assert "2.32.0" in p
    assert "o/r" in p
    assert "#42" in p
    assert "pip-audit" in p or "pip-audit -r" in p  # command hint
    assert "Acceptance criteria" in p


def test_sast_prompt_contains_all_critical_fields():
    f = Finding(
        kind=FindingKind.SAST,
        repo="o/r",
        rule_id="B324",
        title="hashlib weak MD5",
        severity=Severity.HIGH,
        file_path="pkg/util.py",
        line=73,
        code_excerpt="md5_obj = md5()",
        scanner="bandit",
    )
    p = build_prompt(f, target_repo="o/r", issue_number=99)
    assert "B324" in p
    assert "pkg/util.py:73" in p
    assert "md5_obj = md5()" in p
    assert "false positive" in p.lower()
    assert "#99" in p


def test_prompt_mentions_branch_and_pr():
    f = Finding(
        kind=FindingKind.SAST,
        repo="o/r",
        rule_id="B506",
        title="yaml_load",
        severity=Severity.HIGH,
        file_path="x.py",
        line=1,
        scanner="bandit",
    )
    p = build_prompt(f, target_repo="o/r", issue_number=1)
    assert "branch" in p.lower()
    assert "pull request" in p.lower() or "PR" in p
