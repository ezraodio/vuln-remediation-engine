from app.models import Finding, FindingKind, Severity


def _dep(pkg="flask", ver="2.3.3", cve="CVE-2024-0001"):
    return Finding(
        kind=FindingKind.DEP_CVE,
        repo="owner/repo",
        rule_id=cve,
        title=f"{cve} in {pkg}",
        severity=Severity.HIGH,
        package_ecosystem="PyPI",
        package_name=pkg,
        installed_version=ver,
        fixed_versions=["2.3.4"],
        manifest_path="requirements/base.txt",
        scanner="pip-audit",
    )


def _sast(file="a/b.py", line=10):
    return Finding(
        kind=FindingKind.SAST,
        repo="owner/repo",
        rule_id="B324",
        title="weak hash",
        severity=Severity.HIGH,
        file_path=file,
        line=line,
        scanner="bandit",
    )


def test_dep_dedupe_stable_and_distinct():
    a = _dep(cve="CVE-2024-0001")
    b = _dep(cve="CVE-2024-0001")
    c = _dep(cve="CVE-2024-0002")
    d = _dep(pkg="django")
    assert a.dedupe_key() == b.dedupe_key()
    assert a.dedupe_key() != c.dedupe_key()
    assert a.dedupe_key() != d.dedupe_key()


def test_dep_dedupe_ignores_installed_version():
    """Same CVE in same package on two different installed versions is one finding."""
    a = _dep(ver="2.3.3")
    b = _dep(ver="2.3.2")
    assert a.dedupe_key() == b.dedupe_key()


def test_sast_dedupe_ignores_line_number():
    a = _sast(file="a/b.py", line=10)
    b = _sast(file="a/b.py", line=42)
    c = _sast(file="a/c.py", line=10)
    assert a.dedupe_key() == b.dedupe_key()
    assert a.dedupe_key() != c.dedupe_key()


def test_severity_from_cvss():
    assert Severity.from_cvss(9.8) == Severity.CRITICAL
    assert Severity.from_cvss(7.5) == Severity.HIGH
    assert Severity.from_cvss(5.0) == Severity.MEDIUM
    assert Severity.from_cvss(2.0) == Severity.LOW
    assert Severity.from_cvss(None) == Severity.MEDIUM


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank() > Severity.HIGH.rank()
    assert Severity.HIGH.rank() > Severity.MEDIUM.rank()
    assert Severity.MEDIUM.rank() > Severity.LOW.rank()


def test_human_title_dep():
    assert "CVE-2024-0001" in _dep().human_title()
    assert "flask" in _dep().human_title()
    assert "2.3.4" in _dep().human_title()


def test_human_title_sast():
    t = _sast().human_title()
    assert "B324" in t
    assert "a/b.py" in t
