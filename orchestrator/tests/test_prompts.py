"""Tests for the Devin prompt builder."""
from __future__ import annotations

from app.models import Finding, FindingKind, Severity
from app.prompts import build_prompt


def _dep() -> Finding:
    return Finding(
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


def _sast() -> Finding:
    return Finding(
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


def test_dep_prompt_contains_all_critical_fields():
    p = build_prompt(_dep(), target_repo="o/r", issue_number=42)
    for needle in [
        "CVE-2025-1234",
        "requests",
        "2.30.0",
        "2.32.0",
        "o/r",
        "#42",
        "pip-audit",
        "Acceptance criteria",
    ]:
        assert needle in p, f"missing: {needle!r}"


def test_sast_prompt_contains_all_critical_fields():
    p = build_prompt(_sast(), target_repo="o/r", issue_number=99)
    assert "B324" in p
    assert "pkg/util.py:73" in p
    assert "md5_obj = md5()" in p
    assert "false positive" in p.lower()
    assert "#99" in p


def test_prompt_mentions_branch_and_pr():
    p = build_prompt(_sast(), target_repo="o/r", issue_number=1)
    assert "branch" in p.lower()
    assert "pull request" in p.lower() or "PR" in p


def test_prompt_requires_full_test_suite():
    """The critical verification contract: Devin must run the full test suite."""
    p = build_prompt(_dep(), target_repo="o/r", issue_number=1)
    assert "pytest" in p
    assert "test" in p.lower()
    # The acceptance block must mandate pasting the test summary into the PR.
    assert "## Tests" in p


def test_prompt_requires_scanner_output_in_pr_body():
    p = build_prompt(_sast(), target_repo="o/r", issue_number=1)
    assert "## Scanner re-scan" in p
    assert "Paste" in p or "paste" in p


def test_prompt_tells_devin_not_to_open_pr_on_test_failure():
    """Safety: Devin must NOT open a PR if the test suite is red."""
    p = build_prompt(_sast(), target_repo="o/r", issue_number=1)
    assert "do not open the PR" in p or "do not open" in p.lower()


def test_prompt_covers_false_positive_guidance_for_sast_only():
    sast = build_prompt(_sast(), target_repo="o/r", issue_number=1)
    dep = build_prompt(_dep(), target_repo="o/r", issue_number=1)
    # SAST prompt must explain how to suppress with `# nosec`.
    assert "nosec" in sast
    # Dep CVE prompt doesn't need false-positive guidance — CVEs are authoritative.
    assert "nosec" not in dep


def test_prompt_respects_base_branch_override():
    p = build_prompt(_sast(), target_repo="o/r", issue_number=1, base_branch="master")
    assert "from `master`" in p
    # The default-branch fallback must not appear anywhere in the emitted
    # branch/PR commands when an explicit base_branch is passed.
    assert "from `main`" not in p
    assert "against `main`" not in p


def test_prompt_closes_issue_reference():
    """`Closes #N` is how we auto-close the tracking issue on PR merge."""
    p = build_prompt(_dep(), target_repo="o/r", issue_number=123)
    assert "Closes #123" in p


def test_sast_prompt_uses_bandit_flags_not_bare_scanner_name():
    """Regression: earlier versions emitted the bare scanner name ("bandit")
    as the re-scan command, which is not actually runnable."""
    p = build_prompt(_sast(), target_repo="o/r", issue_number=1)
    assert "bandit -r" in p
    assert "-ll" in p


def test_semgrep_rescan_is_runnable():
    f = _sast()
    f.scanner = "semgrep"
    p = build_prompt(f, target_repo="o/r", issue_number=1)
    assert "semgrep scan" in p
