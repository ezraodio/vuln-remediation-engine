"""Tests for the Verifier: clean / still_vuln / unknown branches."""
from __future__ import annotations

import pytest

from app.models import RemediationRecord, RemediationStatus
from app.time_utils import now_utc
from app.verifier import Verifier, VerifyOutcome, VerifyReport

from .conftest import make_sast_finding


class _RecordingDevin:
    """In-memory Devin client that records every call rather than hitting the API."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    async def send_message(self, session_id: str, message: str) -> None:
        self.messages.append((session_id, message))


class _RecordingGitHub:
    def __init__(self) -> None:
        self.comments: list[tuple[str, int, str]] = []
        self.closed: list[tuple[str, int]] = []

    async def comment_issue(self, repo: str, number: int, body: str) -> None:
        self.comments.append((repo, number, body))

    async def close_issue(
        self, repo: str, number: int, *, reason: str = "completed"
    ) -> None:
        self.closed.append((repo, number))


def _seed_record(store, *, session_id: str = "sess-1", issue_number: int = 7):
    f = make_sast_finding()
    key = f.dedupe_key()
    now = now_utc()
    store.upsert(
        RemediationRecord(
            dedupe_key=key,
            finding=f,
            status=RemediationStatus.PR_OPENED,
            issue_number=issue_number,
            issue_url=f"https://github.com/{f.repo}/issues/{issue_number}",
            session_id=session_id,
            session_url=f"https://app.devin.ai/sessions/{session_id}",
            pr_url=f"https://github.com/{f.repo}/pull/99",
            created_at=now,
            updated_at=now,
        )
    )
    return key, f


@pytest.mark.asyncio
async def test_clean_marks_verified_fixed_and_resolves(tmp_store):
    devin, gh = _RecordingDevin(), _RecordingGitHub()
    v = Verifier(store=tmp_store, devin=devin, gh=gh)
    key, _ = _seed_record(tmp_store)

    await v.handle_report(
        VerifyReport(
            dedupe_key=key,
            pr_url="https://github.com/o/r/pull/99",
            outcome=VerifyOutcome.CLEAN,
        )
    )

    updated = tmp_store.get(key)
    assert updated is not None
    assert updated.status == RemediationStatus.VERIFIED_FIXED
    assert updated.resolved_at is not None
    assert devin.messages == []
    assert len(gh.comments) == 1
    assert "no longer reported" in gh.comments[0][2]
    assert gh.closed == [("o/r", 7)]


@pytest.mark.asyncio
async def test_still_vulnerable_messages_same_session(tmp_store):
    devin, gh = _RecordingDevin(), _RecordingGitHub()
    v = Verifier(store=tmp_store, devin=devin, gh=gh)
    key, _ = _seed_record(tmp_store, session_id="sess-abc")

    await v.handle_report(
        VerifyReport(
            dedupe_key=key,
            pr_url="https://github.com/o/r/pull/99",
            outcome=VerifyOutcome.STILL_VULNERABLE,
            scanner_output="B324: still present at line 73",
        )
    )

    updated = tmp_store.get(key)
    assert updated is not None
    assert updated.status == RemediationStatus.VERIFICATION_FAILED
    # resolved_at must remain unset so MTTR isn't tainted by the failed attempt.
    assert updated.resolved_at is None
    assert len(devin.messages) == 1
    sess, msg = devin.messages[0]
    assert sess == "sess-abc"
    assert "STILL present" in msg
    assert "B324: still present at line 73" in msg


@pytest.mark.asyncio
async def test_report_for_unknown_key_is_noop(tmp_store):
    devin, gh = _RecordingDevin(), _RecordingGitHub()
    v = Verifier(store=tmp_store, devin=devin, gh=gh)

    # No record seeded; handle_report must not raise and must not message Devin.
    await v.handle_report(
        VerifyReport(dedupe_key="nope-1234", outcome=VerifyOutcome.CLEAN)
    )

    assert devin.messages == []
    assert gh.comments == []
