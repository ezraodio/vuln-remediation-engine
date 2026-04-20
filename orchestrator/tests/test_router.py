from app.models import Severity
from app.router import Router

from .conftest import make_dep_finding, make_sast_finding


def test_below_severity_is_skipped():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    d = r.decide(make_dep_finding(severity=Severity.LOW, cvss=3.0))
    assert d.action == "skip"


def test_severity_high_with_low_cvss_passes_because_floor_is_OR():
    """Severity AND CVSS are both floors; passing either dispatches."""
    r = Router(min_severity=Severity.HIGH, min_cvss=9.5)
    d = r.decide(make_dep_finding(severity=Severity.HIGH, cvss=7.5))
    assert d.action == "dispatch_devin"


def test_sast_always_goes_to_devin():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    d = r.decide(make_sast_finding())
    assert d.action == "dispatch_devin"


def test_no_fix_version_goes_to_devin_for_mitigation():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    d = r.decide(make_dep_finding(fixed=[]))
    assert d.action == "dispatch_devin"
    assert "mitigation" in d.reason.lower() or "no patched" in d.reason.lower()


def test_dep_cve_with_fix_dispatches():
    r = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    d = r.decide(make_dep_finding(installed="2.3.3", fixed=["2.4.0", "2.3.4"]))
    assert d.action == "dispatch_devin"
