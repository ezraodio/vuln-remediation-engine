# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Regression tests for the ACU-persist race reported by Devin Review.

``reconcile_session`` loads a record into memory, awaits a Devin API call,
then writes the running ACU total back to the row. A concurrent
``/verify/result`` can transition the same row to a terminal status during
the await. The previous implementation passed ``rec.status`` back to
``update_status``, which unconditionally overwrote the DB's (correct, newer)
terminal status with the (stale, older) in-memory status — resurrecting the
record on the reconcile loop and silently losing the verification outcome.
"""
from __future__ import annotations

from app.models import RemediationRecord, RemediationStatus, Severity
from app.pipeline import RemediationPipeline
from app.router import Router
from app.time_utils import now_utc

from .conftest import FakeSettings, make_sast_finding


async def test_persist_acu_cost_does_not_overwrite_concurrent_terminal_status(
    tmp_store, fake_devin, fake_gh, monkeypatch
):
    """Simulates the exact TOCTOU the race bug describes.

    Scenario:
      1. ``/reconcile`` loads R with status=PR_OPENED into memory.
      2. ``reconcile_session`` awaits ``get_session`` (yield).
      3. While awaited, ``/verify/result`` flips R to VERIFIED_FIXED in DB.
      4. ``get_session`` returns with a higher acu_cost.
      5. ``_persist_acu_cost`` must write ACU WITHOUT regressing R's status.
    """
    f = make_sast_finding()
    now = now_utc()
    in_memory = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.PR_OPENED,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        acu_cost=1.0,
        created_at=now,
        updated_at=now,
        pr_opened_at=now,
    )
    tmp_store.upsert(in_memory)

    async def fake_get(_session_id):
        # The concurrent verifier transition happens while the caller is
        # awaiting this coroutine. Emulated by mutating the DB here before
        # returning the Devin payload with a higher acu_cost.
        tmp_store.update_status(
            in_memory.dedupe_key,
            RemediationStatus.VERIFIED_FIXED,
            mark_resolved=True,
        )
        return {
            "session_id": "sess-1",
            "status": "running",
            "pull_requests": [{"url": "https://github.com/o/r/pull/7"}],
            "acu_cost": 5.0,
        }

    monkeypatch.setattr(fake_devin, "get_session", fake_get)
    pipeline = RemediationPipeline(
        settings=FakeSettings(),
        store=tmp_store,
        devin=fake_devin,
        gh=fake_gh,
        router=Router(min_severity=Severity.HIGH, min_cvss=7.0),
    )

    # Call with the stale in-memory snapshot — as /reconcile would.
    await pipeline.reconcile_session(in_memory)

    after = tmp_store.get(in_memory.dedupe_key)
    assert after.status == RemediationStatus.VERIFIED_FIXED, (
        "concurrent verifier transition was overwritten by stale reconcile"
    )
    assert after.resolved_at is not None
    assert after.acu_cost == 5.0, "ACU update should still land"


def test_update_acu_cost_narrow_write_leaves_other_fields_alone(tmp_store):
    """``update_acu_cost`` must not touch status, pr_url, or session_id."""
    f = make_sast_finding()
    now = now_utc()
    rec = RemediationRecord(
        dedupe_key=f.dedupe_key(),
        finding=f,
        status=RemediationStatus.VERIFIED_FIXED,
        session_id="sess-1",
        issue_number=1,
        pr_url="https://github.com/o/r/pull/7",
        acu_cost=2.0,
        created_at=now,
        updated_at=now,
        pr_opened_at=now,
        resolved_at=now,
    )
    tmp_store.upsert(rec)

    tmp_store.update_acu_cost(rec.dedupe_key, 7.5)

    after = tmp_store.get(rec.dedupe_key)
    assert after.status == RemediationStatus.VERIFIED_FIXED
    assert after.pr_url == "https://github.com/o/r/pull/7"
    assert after.session_id == "sess-1"
    assert after.resolved_at is not None
    assert after.acu_cost == 7.5
