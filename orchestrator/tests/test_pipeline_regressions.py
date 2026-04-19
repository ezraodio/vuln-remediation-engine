"""Regression harness for pipeline-layer bugs found in the second audit pass.

Each test is named after the bug it prevents. Keep these tests small and
focused — failure should immediately point at the specific invariant that
regressed.
"""
from __future__ import annotations

import asyncio

from app.models import RemediationStatus, Severity
from app.pipeline import RemediationPipeline
from app.router import Router

from .conftest import FakeSettings, make_dep_finding, make_sast_finding


def _pipeline(tmp_store, fake_devin, fake_gh, *, dry_run: bool = False):
    settings = FakeSettings()
    settings.dry_run = dry_run
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    return RemediationPipeline(
        settings=settings,
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=router,
    )


async def test_dry_run_does_not_touch_target_repo(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """DRY_RUN=true must not open a tracking issue or a Devin session."""
    p = _pipeline(tmp_store, fake_devin, fake_gh, dry_run=True)

    async def boom_create_issue(*_a, **_kw):
        raise AssertionError("dry-run must not call gh.create_issue")

    async def boom_create_session(*_a, **_kw):
        raise AssertionError("dry-run must not call devin.create_session")

    monkeypatch.setattr(fake_gh, "create_issue", boom_create_issue)
    monkeypatch.setattr(fake_devin, "create_session", boom_create_session)

    result = await p.handle_finding(make_dep_finding(), source="test")
    assert result.status == RemediationStatus.FILTERED
    assert result.reason == "DRY_RUN=true"


async def test_concurrent_ingest_of_same_key_dispatches_exactly_once(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Two simultaneous POSTs with the same dedupe_key must serialize:
    exactly one wins dispatch, the other is deduped.

    Regression net for the TOCTOU race between _deduped_locally (SQLite
    read) and the upsert inside _dispatch_devin.
    """
    p = _pipeline(tmp_store, fake_devin, fake_gh)

    dispatches: list[str] = []
    orig_create = fake_devin.create_session

    async def counting_create(**kwargs):
        dispatches.append(kwargs.get("title", "?"))
        # Yield the loop at least once to widen the race window — if there
        # were no lock, the second concurrent call could still miss the
        # first's commit here.
        await asyncio.sleep(0)
        return await orig_create(**kwargs)

    monkeypatch.setattr(fake_devin, "create_session", counting_create)

    f = make_dep_finding()
    r1, r2 = await asyncio.gather(
        p.handle_finding(f, source="a"),
        p.handle_finding(f, source="b"),
    )
    statuses = sorted([r1.status.value, r2.status.value])
    assert statuses == ["deduped", "dispatched"]
    assert len(dispatches) == 1


async def test_handle_finding_is_reentrant_after_lock_release(
    tmp_store, fake_devin, fake_gh
):
    """After the first call completes, a subsequent call with the same key
    must re-acquire the lock without deadlock and return DEDUPED."""
    p = _pipeline(tmp_store, fake_devin, fake_gh)
    f = make_sast_finding()
    r1 = await p.handle_finding(f, source="a")
    r2 = await p.handle_finding(f, source="b")
    assert r1.status == RemediationStatus.DISPATCHED
    assert r2.status == RemediationStatus.DEDUPED
