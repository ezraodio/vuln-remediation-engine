"""Tests that a request_id flows end-to-end: /ingest header → DB record →
Devin session tag → GitHub issue body. Covers the interview-grade
"how do I trace a single request across subsystems" story.
"""
from __future__ import annotations

from app.devin_client import DevinClient
from app.github_client import GitHubClient
from app.models import Severity
from app.pipeline import RemediationPipeline
from app.router import Router

from .conftest import FakeSettings, make_sast_finding


class _RecordingDevin(DevinClient):
    """Captures the exact kwargs the pipeline sends to create_session so we
    can assert the request_id tag without talking to the real API."""

    def __init__(self):
        super().__init__(api_key="x", org_id="y", mock=True)
        self.last_create_kwargs: dict | None = None

    async def create_session(self, **kw):  # type: ignore[override]
        self.last_create_kwargs = kw
        return {
            "session_id": "sess-mock",
            "url": "https://app.devin.ai/sessions/sess-mock",
        }


class _RecordingGitHub(GitHubClient):
    """Captures the issue body so we can assert request_id made it in."""

    def __init__(self):
        super().__init__(token="x", mock=True)
        self.last_issue_body: str | None = None

    async def create_issue(self, repo, *, title, body, labels=None):  # type: ignore[override]  # noqa: ARG002
        self.last_issue_body = body
        return {"number": 42, "html_url": f"https://github.com/{repo}/issues/42"}


async def _run_pipeline(store, request_id):
    devin = _RecordingDevin()
    gh = _RecordingGitHub()
    pipeline = RemediationPipeline(
        settings=FakeSettings(),
        store=store,
        devin=devin,
        gh=gh,
        router=Router(min_severity=Severity.HIGH, min_cvss=7.0),
    )
    finding = make_sast_finding()
    await pipeline.handle_finding(
        finding, source="test", request_id=request_id
    )
    return devin, gh, finding


async def test_request_id_is_tagged_on_devin_session(tmp_store):
    devin, _gh, _f = await _run_pipeline(tmp_store, "rid-abc123")
    tags = devin.last_create_kwargs["tags"]
    assert "req:rid-abc123" in tags


async def test_request_id_embedded_in_issue_body(tmp_store):
    _devin, gh, _f = await _run_pipeline(tmp_store, "rid-xyz789")
    assert "rid-xyz789" in gh.last_issue_body
    # And available to the verifier via the machine-readable comment.
    assert '"request_id":"rid-xyz789"' in gh.last_issue_body


async def test_request_id_persisted_on_remediation_record(tmp_store):
    _devin, _gh, f = await _run_pipeline(tmp_store, "rid-persist")
    rec = tmp_store.get(f.dedupe_key())
    assert rec is not None
    assert rec.request_id == "rid-persist"


async def test_missing_request_id_is_auto_generated(tmp_store):
    devin = _RecordingDevin()
    gh = _RecordingGitHub()
    pipeline = RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=devin,
        gh=gh,
        router=Router(min_severity=Severity.HIGH, min_cvss=7.0),
    )
    await pipeline.handle_finding(make_sast_finding(), source="test")
    # Exactly one req: tag, non-empty, not the literal "None".
    req_tags = [t for t in devin.last_create_kwargs["tags"] if t.startswith("req:")]
    assert len(req_tags) == 1
    assert req_tags[0] != "req:" and req_tags[0] != "req:None"
