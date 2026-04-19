"""_deduped_by_session: happy-path and inactive-session coverage.

FakeDevinClient.list_sessions_by_tag always returns [], so the "active
session exists" branch was never exercised before this test. Regression
net for: (a) dedupe key short-circuits create_session when a tagged
session is already running, (b) inactive sessions don't short-circuit.
"""
from __future__ import annotations

from app.models import RemediationStatus, Severity
from app.pipeline import RemediationPipeline
from app.router import Router

from .conftest import FakeSettings, make_dep_finding


def _pipeline(tmp_store, fake_devin, fake_gh):
    router = Router(min_severity=Severity.HIGH, min_cvss=7.0)
    return RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=router,
    )


async def test_active_session_short_circuits_dispatch(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    p = _pipeline(tmp_store, fake_devin, fake_gh)
    f = make_dep_finding()
    tag = f"vuln:{f.dedupe_key()}"

    async def fake_list(t, **_):
        assert t == tag, f"expected lookup by {tag!r}, got {t!r}"
        return [
            {
                "session_id": "sess-active",
                "url": "https://app.devin.ai/sessions/sess-active",
                "status": "running",
                "tags": [tag],
            }
        ]

    async def boom_create(**_):
        raise AssertionError("create_session must NOT be called when active session exists")

    monkeypatch.setattr(fake_devin, "list_sessions_by_tag", fake_list)
    monkeypatch.setattr(fake_devin, "create_session", boom_create)

    result = await p.handle_finding(f, source="test")

    assert result.status == RemediationStatus.DEDUPED
    assert result.session_id == "sess-active"

    rec = tmp_store.get(f.dedupe_key())
    assert rec.status == RemediationStatus.SESSION_RUNNING
    assert rec.session_id == "sess-active"


async def test_only_inactive_sessions_do_not_short_circuit(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    p = _pipeline(tmp_store, fake_devin, fake_gh)
    f = make_dep_finding()
    tag = f"vuln:{f.dedupe_key()}"

    async def fake_list(*_a, **_kw):
        return [
            {
                "session_id": "sess-archived",
                "url": "https://app.devin.ai/sessions/sess-archived",
                "status": "stopped",
                "tags": [tag],
            }
        ]

    monkeypatch.setattr(fake_devin, "list_sessions_by_tag", fake_list)

    result = await p.handle_finding(f, source="test")
    assert result.status == RemediationStatus.DISPATCHED
