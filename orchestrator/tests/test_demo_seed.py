"""Smoke test for the demo-seed CLI.

Keeps the seed script honest: it must produce exactly the claimed status
mix (3 VERIFIED_FIXED / 2 PR_OPENED / …) and must be idempotent so a
rerun before a second take doesn't double-seed the dashboard.

The README's "Recording the demo" block depends on this contract.
"""
from __future__ import annotations

import os

from app import demo_seed
from app.db import Store
from app.models import RemediationStatus

EXPECTED_MIX = {
    RemediationStatus.VERIFIED_FIXED: 3,
    RemediationStatus.PR_OPENED: 2,
    RemediationStatus.SESSION_RUNNING: 1,
    RemediationStatus.VERIFICATION_FAILED: 1,
    RemediationStatus.FAILED: 1,
    RemediationStatus.MERGED_UNVERIFIED: 1,
}


def _counts_by_status(store: Store) -> dict[RemediationStatus, int]:
    out: dict[RemediationStatus, int] = {}
    for rec in store.list_all():
        out[rec.status] = out.get(rec.status, 0) + 1
    return out


def test_seed_all_produces_the_mix_the_demo_script_promises(tmp_path):
    store = Store(str(tmp_path / "seed.db"))
    demo_seed.seed_all(store)
    assert _counts_by_status(store) == EXPECTED_MIX
    assert all(
        r.dedupe_key.startswith(demo_seed.DEMO_KEY_PREFIX)
        for r in store.list_all()
    )


def test_seed_is_idempotent_on_rerun(tmp_path):
    store = Store(str(tmp_path / "seed.db"))
    demo_seed.seed_all(store)
    demo_seed.seed_all(store)
    assert _counts_by_status(store) == EXPECTED_MIX


def test_reset_deletes_only_seeded_rows(tmp_store):
    """Reset must NOT clobber pre-existing rows written by the real pipeline."""
    from app.models import RemediationRecord
    from app.time_utils import now_utc

    from .conftest import make_sast_finding

    real = make_sast_finding(rule="B999", file_path="real.py")
    now = now_utc()
    tmp_store.upsert(
        RemediationRecord(
            dedupe_key="real-user-row-please-keep",
            finding=real,
            status=RemediationStatus.PR_OPENED,
            created_at=now,
            updated_at=now,
        )
    )

    demo_seed.seed_all(tmp_store)
    assert len(tmp_store.list_all()) == 1 + sum(EXPECTED_MIX.values())

    demo_seed.reset_demo_rows(tmp_store)
    keys = [r.dedupe_key for r in tmp_store.list_all()]
    assert keys == ["real-user-row-please-keep"]


def test_main_entry_point_runs_cleanly(tmp_path, monkeypatch, capsys):
    """`python -m app.demo_seed --reset` is the command the README ships."""
    db_path = tmp_path / "cli.db"
    monkeypatch.setattr("sys.argv", ["demo_seed", "--db", str(db_path), "--reset"])
    # First invocation: nothing to reset, 9 rows seeded.
    assert demo_seed.main() == 0
    store = Store(str(db_path))
    assert len(store.list_all()) == sum(EXPECTED_MIX.values())

    out = capsys.readouterr().out
    assert "seeded 9 demo rows" in out
    assert "verified_fixed" in out

    # Second invocation: reset kicks in, ends at the same count.
    monkeypatch.setattr("sys.argv", ["demo_seed", "--db", str(db_path), "--reset"])
    assert demo_seed.main() == 0
    assert len(Store(str(db_path)).list_all()) == sum(EXPECTED_MIX.values())


def test_env_var_overrides_db_path(monkeypatch, tmp_path):
    db_path = tmp_path / "env.db"
    monkeypatch.setenv("ORCHESTRATOR_DB_PATH", str(db_path))
    monkeypatch.setattr("sys.argv", ["demo_seed"])
    assert demo_seed.main() == 0
    assert os.path.exists(db_path)
