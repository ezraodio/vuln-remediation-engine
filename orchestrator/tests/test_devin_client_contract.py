"""Contract tests for DevinClient HTTP shape.

Validates the exact requests we send to Devin v3 — path, headers, JSON
body keys. Catches accidental payload drift (e.g., dropping `idempotent`,
wrong tag format, missing Authorization header) that would silently
succeed against the fake DevinClient(mock=True) but fail against the
real API.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from app.devin_client import DevinClient


@pytest.fixture
def devin() -> DevinClient:
    return DevinClient(api_key="cog_test", org_id="org-test", mock=False)


@respx.mock
async def test_create_session_sends_expected_shape(devin):
    route = respx.post(
        "https://api.devin.ai/v3/organizations/org-test/sessions"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"session_id": "sess-1", "url": "https://app.devin.ai/sessions/sess-1"},
        )
    )

    out = await devin.create_session(
        prompt="please fix",
        title="auto-remediation",
        tags=["vuln:abc", "rule:B324"],
        idempotent=True,
    )
    assert out["session_id"] == "sess-1"
    assert route.called
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer cog_test"
    assert req.headers["content-type"] == "application/json"
    body = json.loads(req.content)
    assert body["prompt"] == "please fix"
    assert body["title"] == "auto-remediation"
    assert body["tags"] == ["vuln:abc", "rule:B324"]
    assert body["idempotent"] is True


@respx.mock
async def test_create_session_caps_tags_at_fifty(devin):
    route = respx.post(
        "https://api.devin.ai/v3/organizations/org-test/sessions"
    ).mock(return_value=httpx.Response(200, json={"session_id": "s", "url": "u"}))
    tags = [f"tag-{i}" for i in range(75)]
    await devin.create_session(prompt="p", tags=tags)
    body = json.loads(route.calls.last.request.content)
    assert len(body["tags"]) == 50


@respx.mock
async def test_list_sessions_by_tag_paginates_via_cursor(devin):
    """Busy orgs must not drop matches off the tail — the client follows
    next_cursor rather than client-filtering a single recent page."""
    respx.get("https://api.devin.ai/v3/organizations/org-test/sessions").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "items": [
                        {"session_id": "a", "tags": ["other"]},
                        {"session_id": "b", "tags": ["vuln:xyz"]},
                    ],
                    "next_cursor": "CURSOR-1",
                },
            ),
            httpx.Response(
                200,
                json={
                    "items": [
                        {"session_id": "c", "tags": ["vuln:xyz"]},
                        {"session_id": "d", "tags": ["other"]},
                    ],
                    "next_cursor": None,
                },
            ),
        ]
    )
    out = await devin.list_sessions_by_tag("vuln:xyz")
    assert [s["session_id"] for s in out] == ["b", "c"]


@respx.mock
async def test_send_message_posts_to_session(devin):
    route = respx.post(
        "https://api.devin.ai/v3/organizations/org-test/sessions/sess-1/message"
    ).mock(return_value=httpx.Response(200, json={}))
    await devin.send_message("sess-1", "iterate please")
    body = json.loads(route.calls.last.request.content)
    assert body == {"message": "iterate please"}


@respx.mock
async def test_create_session_raises_on_4xx(devin):
    respx.post(
        "https://api.devin.ai/v3/organizations/org-test/sessions"
    ).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    with pytest.raises(httpx.HTTPError):
        await devin.create_session(prompt="p")


def test_session_is_active_respects_status():
    d = DevinClient(api_key="x", org_id="y", mock=True)
    for s in ("running", "starting", "queued", "pending", "working"):
        assert d.session_is_active({"status": s}) is True, s
    for s in ("stopped", "finished", "blocked", ""):
        assert d.session_is_active({"status": s}) is False, s
    assert (
        d.session_is_active({"status": "running", "is_archived": True}) is False
    )
