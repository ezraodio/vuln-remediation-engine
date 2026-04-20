"""Regression tests for bugs surfaced in the Round-6 interview-grade audit.

One test per bug, named after the invariant it pins down so a regression
points directly at the broken contract:

* ``test_dispatch_failure_swallows_github_comment_error`` — when Devin
  dispatch fails AND the follow-up tracking-issue comment also fails,
  ``/ingest`` must still return a FAILED result. Previously the second
  ``httpx.HTTPError`` propagated through to FastAPI and the request 500'd
  after state was already persisted, causing scanner retries to re-dispatch
  work we'd already recorded as failed.
* ``test_router_raises_on_unknown_finding_kind`` — silently returning
  ``dispatch_devin`` for an unhandled kind is dead code that masks misuse;
  new kinds must be explicit.
* ``test_lock_map_empty_after_concurrent_ingests`` — lock eviction uses an
  explicit refcount (no reliance on ``asyncio.Lock._waiters``) and the map
  is fully drained once every in-flight waiter releases.
* ``test_stale_pr_flag_fires_when_github_state_unknown`` — a PR we can't
  reach on GitHub (deleted, transient 5xx) must still transition to
  NEEDS_ATTENTION once it ages past the flag threshold, instead of
  stranding the record in PR_OPENED forever.
* ``test_list_sessions_by_tag_doesnt_loop_on_stale_cursor`` — the client
  follows ``next_cursor`` only; an API that echoes the request cursor back
  as ``cursor`` must not drive us in a loop.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
import pytest
import respx

from app.devin_client import DevinClient
from app.models import (
    RemediationRecord,
    RemediationStatus,
    Severity,
)
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc

from .conftest import FakeSettings, make_dep_finding, make_sast_finding


def _pipeline(tmp_store, fake_devin, fake_gh):
    settings = FakeSettings()
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    return RemediationPipeline(
        settings=settings,
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=router,
    )


# --------------------------------------------------------------------------- #
# B1 — dispatch-failure comment path must not 500 the ingest endpoint         #
# --------------------------------------------------------------------------- #


async def test_dispatch_failure_swallows_github_comment_error(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    p = _pipeline(tmp_store, fake_devin, fake_gh)

    async def boom_create_session(**_kw):
        raise httpx.ConnectError("devin down")

    async def boom_comment_issue(*_a, **_kw):
        raise httpx.ConnectError("github flap")

    monkeypatch.setattr(fake_devin, "create_session", boom_create_session)
    monkeypatch.setattr(fake_gh, "comment_issue", boom_comment_issue)

    result = await p.handle_finding(make_dep_finding(), source="test")

    assert result.status == RemediationStatus.FAILED
    assert "Devin dispatch failed" in (result.reason or "")
    rec = tmp_store.get(result.dedupe_key)
    assert rec is not None
    assert rec.status == RemediationStatus.FAILED


# --------------------------------------------------------------------------- #
# B2 — router must refuse unknown FindingKind (no dead default)               #
# --------------------------------------------------------------------------- #


def test_router_raises_on_unknown_finding_kind():
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    f = make_sast_finding()
    object.__setattr__(f, "kind", "novel_kind_not_in_enum")
    with pytest.raises(NotImplementedError):
        router.decide(f)


# --------------------------------------------------------------------------- #
# B3 — lock cleanup via explicit refcount, not private asyncio internals      #
# --------------------------------------------------------------------------- #


async def test_lock_map_empty_after_concurrent_ingests(
    tmp_store, fake_devin, fake_gh
):
    """Map drains after every caller releases, regardless of how many were
    concurrently waiting on the same key. Guards against the previous
    ``_waiters``-reflection heuristic that could leave stale entries on
    future Python releases where the private attribute moves or changes
    shape.
    """
    p = _pipeline(tmp_store, fake_devin, fake_gh)
    f = make_dep_finding()

    results = await asyncio.gather(
        *[p.handle_finding(f, source=f"r{i}") for i in range(5)]
    )
    statuses = sorted(r.status.value for r in results)
    assert statuses.count("dispatched") == 1
    assert statuses.count("deduped") == 4
    assert p._key_locks == {}
    assert p._key_lock_refcount == {}


# --------------------------------------------------------------------------- #
# B5 — age-based NEEDS_ATTENTION flag must fire even when GH state is unknown #
# --------------------------------------------------------------------------- #


async def test_stale_pr_flag_fires_when_github_state_unknown(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    p = _pipeline(tmp_store, fake_devin, fake_gh)
    f = make_sast_finding()
    opened = now_utc() - timedelta(hours=72)
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-x",
        pr_url="https://github.com/o/r/pull/999",
        created_at=opened,
        updated_at=opened,
        pr_opened_at=opened,
    )
    tmp_store.upsert(rec)

    async def unknown_state(_url):
        return None

    async def get_session(_sid):
        return {"session_id": _sid, "status": "running", "pull_requests": [{"url": rec.pr_url}]}

    monkeypatch.setattr(fake_gh, "get_pr_state", unknown_state)
    monkeypatch.setattr(fake_devin, "get_session", get_session)

    await p.reconcile_session(rec)

    advanced = tmp_store.get(rec.dedupe_key)
    assert advanced.status == RemediationStatus.NEEDS_ATTENTION


# --------------------------------------------------------------------------- #
# B7 — list_sessions_by_tag must not infinite-loop on echoed cursor           #
# --------------------------------------------------------------------------- #


@respx.mock
async def test_list_sessions_by_tag_doesnt_loop_on_stale_cursor():
    """An API that echoes the request cursor back as ``cursor`` (instead of
    ``next_cursor``) previously drove the client in a loop up to
    ``max_pages``, duplicating items each iteration. The client now follows
    ``next_cursor`` exclusively and dedupes by session_id so a pagination
    bug upstream cannot silently inflate the match list.
    """
    client = DevinClient(api_key="k", org_id="org-test", mock=False)
    respx.get("https://api.devin.ai/v3/organizations/org-test/sessions").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {"session_id": "only", "tags": ["vuln:abc"]},
                ],
                "cursor": "echoed-not-next",
            },
        )
    )
    out = await client.list_sessions_by_tag("vuln:abc", max_pages=5)
    assert [s["session_id"] for s in out] == ["only"]
