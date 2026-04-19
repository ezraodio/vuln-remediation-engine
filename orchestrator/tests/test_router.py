from app.models import Finding, FindingKind, Severity
from app.router import Router


def _mk(severity=Severity.HIGH, kind=FindingKind.DEP_CVE, installed="2.3.3", fixed=None, cvss=7.5):
    if fixed is None:
        fixed = ["2.3.4"] if kind == FindingKind.DEP_CVE else []
    return Finding(
        kind=kind,
        repo="o/r",
        rule_id="CVE-x",
        title="t",
        severity=severity,
        cvss=cvss,
        package_ecosystem="PyPI" if kind == FindingKind.DEP_CVE else None,
        package_name="flask" if kind == FindingKind.DEP_CVE else None,
        installed_version=installed,
        fixed_versions=fixed,
        file_path="a/b.py" if kind == FindingKind.SAST else None,
        line=10 if kind == FindingKind.SAST else None,
        scanner="test",
    )


def test_below_severity_is_skipped():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="dispatch")
    d = r.decide(_mk(severity=Severity.LOW, cvss=3.0))
    assert d.action == "skip"


def test_sast_always_goes_to_devin():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="bump_pr")
    d = r.decide(_mk(kind=FindingKind.SAST))
    assert d.action == "dispatch_devin"


def test_no_fix_goes_to_devin_for_mitigation():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="dispatch")
    d = r.decide(_mk(fixed=[]))
    assert d.action == "dispatch_devin"
    assert "mitigation" in d.reason.lower() or "no patched" in d.reason.lower()


def test_trivial_patch_bump_with_bump_pr_strategy():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="bump_pr")
    d = r.decide(_mk(installed="2.3.3", fixed=["2.3.4"]))
    assert d.action == "open_bump_pr"
    assert d.bump_target == "2.3.4"


def test_non_trivial_minor_bump_goes_to_devin():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="bump_pr")
    d = r.decide(_mk(installed="2.3.3", fixed=["2.4.0"]))
    assert d.action == "dispatch_devin"


def test_skip_strategy_delegates_to_dependabot():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="skip")
    d = r.decide(_mk())
    assert d.action == "skip"
    assert "dependabot" in d.reason.lower()


def test_dispatch_strategy_always_uses_devin():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0, bump_strategy="dispatch")
    d = r.decide(_mk(installed="2.3.3", fixed=["2.3.4"]))
    assert d.action == "dispatch_devin"
