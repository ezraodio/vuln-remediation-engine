"""End-to-end dedupe test using mock clients."""
from __future__ import annotations

import pytest

from app.models import Severity
from app.pipeline import RemediationPipeline
from app.router import Router

from .conftest import FakeSettings, make_dep_finding


@pytest.fixture
def pipeline(tmp_store, fake_devin, fake_gh):
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    return RemediationPipeline(
        settings=FakeSettings(), store=tmp_store, devin=fake_devin, gh=fake_gh, router=router
    )


async def test_dedupe_on_second_submit(pipeline):
    r1 = await pipeline.handle_finding(make_dep_finding(), source="test")
    assert r1.status.value == "dispatched"
    r2 = await pipeline.handle_finding(make_dep_finding(), source="test")
    assert r2.status.value == "deduped"
    assert r2.reason is not None


async def test_different_rule_is_not_deduped(pipeline):
    await pipeline.handle_finding(make_dep_finding(rule="CVE-1"), source="test")
    r = await pipeline.handle_finding(make_dep_finding(rule="CVE-2"), source="test")
    assert r.status.value == "dispatched"


async def test_severity_filter(pipeline):
    f = make_dep_finding(severity=Severity.LOW, cvss=2.0)
    r = await pipeline.handle_finding(f, source="test")
    assert r.status.value == "filtered"
