"""Contract tests for GitHubClient HTTP shape.

Validates the exact requests we send to GitHub — path, headers, query
string, JSON body. Catches accidental payload drift (e.g., wrong label
param, missing api-version header) that would silently succeed against
a mock but fail at runtime.

Also covers the pagination fix in find_open_issue_by_label: with >100
open issues under a label, the marker must still be found even if it
lives on a later page.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.github_client import GitHubClient


@pytest.fixture
def gh() -> GitHubClient:
    return GitHubClient(token="test-token", mock=False)


@respx.mock
async def test_create_issue_sends_expected_shape(gh):
    # create_issue first calls ensure_label which does a GET; we return 200
    # so the POST-create-label branch is skipped.
    respx.get("https://api.github.com/repos/o/r/labels/devin-remediation").mock(
        return_value=httpx.Response(200, json={"name": "devin-remediation"})
    )
    create = respx.post("https://api.github.com/repos/o/r/issues").mock(
        return_value=httpx.Response(
            201,
            json={"number": 42, "html_url": "https://github.com/o/r/issues/42"},
        )
    )

    out = await gh.create_issue(
        "o/r", title="T", body="B", labels=["devin-remediation", "severity:high"]
    )
    assert out["number"] == 42
    assert create.called
    req = create.calls.last.request
    assert req.headers["authorization"] == "Bearer test-token"
    assert req.headers["x-github-api-version"] == "2022-11-28"
    assert req.headers["accept"] == "application/vnd.github+json"
    import json as _json

    body = _json.loads(req.content)
    assert body == {"title": "T", "body": "B", "labels": ["devin-remediation", "severity:high"]}


@respx.mock
async def test_find_open_issue_paginates_until_marker_found(gh):
    page1 = [
        {"number": i, "body": "nope", "pull_request": None} for i in range(1, 101)
    ]
    page2 = [
        {"number": 101, "body": "nope", "pull_request": None},
        {"number": 202, "body": "marker=`abc123` found", "pull_request": None},
    ]
    respx.get("https://api.github.com/repos/o/r/issues").mock(
        side_effect=[
            httpx.Response(200, json=page1),
            httpx.Response(200, json=page2),
        ]
    )

    out = await gh.find_open_issue_by_label("o/r", "devin-remediation", marker="`abc123`")
    assert out is not None
    assert out["number"] == 202


@respx.mock
async def test_find_open_issue_skips_pull_requests(gh):
    respx.get("https://api.github.com/repos/o/r/issues").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 1,
                    "body": "`abc123`",
                    "pull_request": {"url": "https://api.github.com/..."},
                },
                {"number": 2, "body": "`abc123`", "pull_request": None},
            ],
        )
    )
    out = await gh.find_open_issue_by_label("o/r", "devin-remediation", marker="`abc123`")
    assert out is not None
    assert out["number"] == 2


@respx.mock
async def test_find_open_issue_returns_none_when_not_found(gh):
    respx.get("https://api.github.com/repos/o/r/issues").mock(
        return_value=httpx.Response(200, json=[])
    )
    assert await gh.find_open_issue_by_label("o/r", "l", marker="m") is None


@respx.mock
async def test_comment_issue_raises_on_4xx(gh):
    respx.post("https://api.github.com/repos/o/r/issues/1/comments").mock(
        return_value=httpx.Response(404, json={"message": "not found"})
    )
    with pytest.raises(httpx.HTTPError):
        await gh.comment_issue("o/r", 1, "hello")
