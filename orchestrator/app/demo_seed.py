#!/usr/bin/env python3
"""Populate the orchestrator's SQLite store with a realistic state mix.

Intended for demo / Loom recording: a cold-start dashboard shows zeros
and tells no story, so before recording we seed representative rows
across every status the UI cares about (terminal success + in-flight +
stale + terminal failure). Running this twice is safe — seeded rows
share a deterministic ``demo-seed-*`` dedupe key prefix, so a second
run reconciles to the same state instead of doubling it.

Usage (from inside the container):
    docker compose exec orchestrator python -m app.demo_seed --reset

Usage (from a host shell in orchestrator/):
    python -m app.demo_seed --db ./data/orchestrator.db --reset

The script bypasses /ingest deliberately: we want specific *terminal*
statuses for the screenshot (VERIFIED_FIXED with green checks in the
heatmap), which an in-process pipeline can't reach without a real Devin
session. Reaching into the Store here is safe because demo seeding is
not on any production path.
"""
from __future__ import annotations

import argparse
import os
from datetime import timedelta

from .db import Store
from .models import (
    Finding,
    FindingKind,
    RemediationRecord,
    RemediationStatus,
    Severity,
)
from .time_utils import now_utc

DEMO_KEY_PREFIX = "demo-seed-"
TARGET_REPO = os.environ.get("DEMO_TARGET_REPO", "ezraodio/superset")


def _dep_finding(
    *,
    rule: str,
    pkg: str,
    installed: str,
    fixed: list[str],
    severity: Severity,
    cvss: float,
    manifest: str = "requirements/base.txt",
) -> Finding:
    return Finding(
        kind=FindingKind.DEP_CVE,
        repo=TARGET_REPO,
        rule_id=rule,
        title=f"{rule} in {pkg}",
        severity=severity,
        cvss=cvss,
        package_ecosystem="PyPI",
        package_name=pkg,
        installed_version=installed,
        fixed_versions=fixed,
        manifest_path=manifest,
        scanner="pip-audit",
    )


def _sast_finding(
    *,
    rule: str,
    file_path: str,
    line: int,
    severity: Severity,
    title: str | None = None,
) -> Finding:
    return Finding(
        kind=FindingKind.SAST,
        repo=TARGET_REPO,
        rule_id=rule,
        title=title or f"{rule} at {file_path}",
        severity=severity,
        file_path=file_path,
        line=line,
        scanner="bandit",
    )


def _seed(
    store: Store,
    *,
    slug: str,
    finding: Finding,
    status: RemediationStatus,
    hours_ago: float,
    issue_number: int,
    pr_url: str | None = None,
    pr_hours_ago: float | None = None,
    acu_cost: float | None = None,
    resolved: bool = False,
) -> None:
    key = f"{DEMO_KEY_PREFIX}{slug}"
    created = now_utc() - timedelta(hours=hours_ago)
    rec = RemediationRecord(
        dedupe_key=key,
        finding=finding,
        status=status,
        issue_number=issue_number,
        issue_url=f"https://github.com/{finding.repo}/issues/{issue_number}",
        session_id=f"sess-{slug}",
        session_url=f"https://app.devin.ai/sessions/sess-{slug}",
        pr_url=pr_url,
        acu_cost=acu_cost,
        created_at=created,
        updated_at=now_utc(),
        pr_opened_at=(
            now_utc() - timedelta(hours=pr_hours_ago)
            if pr_hours_ago is not None
            else None
        ),
        resolved_at=now_utc() if resolved else None,
    )
    store.upsert(rec)
    store.log_event(key, "demo_seed", {"status": status.value, "slug": slug})


def seed_all(store: Store) -> list[tuple[str, str]]:
    """Seed one representative row per status. Returns (slug, status) list.

    The mix is tuned for a 4-min demo screenshot: 3 VERIFIED_FIXED rows
    (success rate is non-zero and meaningful), 2 PR_OPENED (live in-flight
    work, one of them stale → NEEDS_ATTENTION-ready), 1 SESSION_RUNNING
    (show Devin mid-task), 1 VERIFICATION_FAILED (feedback loop evidence),
    1 FAILED (honest failure representation), 1 MERGED_UNVERIFIED (humans
    sometimes ship without the re-scan closing the loop).
    """
    plan: list[tuple[dict, RemediationStatus]] = [
        # --- Terminal success: 3 VERIFIED_FIXED so success_rate / MTTR mean something
        (
            dict(
                slug="md5-hashing",
                finding=_sast_finding(
                    rule="B324",
                    file_path="superset/utils/hashing.py",
                    line=73,
                    severity=Severity.HIGH,
                    title="Use of weak MD5 hash",
                ),
                hours_ago=48,
                issue_number=1,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/4",
                pr_hours_ago=47,
                acu_cost=3.2,
                resolved=True,
            ),
            RemediationStatus.VERIFIED_FIXED,
        ),
        (
            dict(
                slug="yaml-load",
                finding=_sast_finding(
                    rule="B506",
                    file_path="superset/examples/utils.py",
                    line=41,
                    severity=Severity.HIGH,
                    title="Use of yaml.load without SafeLoader",
                ),
                hours_ago=36,
                issue_number=2,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/5",
                pr_hours_ago=35,
                acu_cost=2.1,
                resolved=True,
            ),
            RemediationStatus.VERIFIED_FIXED,
        ),
        (
            dict(
                slug="urllib3-cve",
                finding=_dep_finding(
                    rule="CVE-2026-39892",
                    pkg="urllib3",
                    installed="1.26.7",
                    fixed=["2.5.0"],
                    severity=Severity.CRITICAL,
                    cvss=9.1,
                ),
                hours_ago=24,
                issue_number=3,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/6",
                pr_hours_ago=23,
                acu_cost=5.4,
                resolved=True,
            ),
            RemediationStatus.VERIFIED_FIXED,
        ),
        # --- Live in-flight: one fresh PR, one already stale (dashboard flags it)
        (
            dict(
                slug="pyyaml-bump",
                finding=_dep_finding(
                    rule="CVE-2025-11111",
                    pkg="pyyaml",
                    installed="5.4.0",
                    fixed=["6.0.1"],
                    severity=Severity.HIGH,
                    cvss=7.5,
                ),
                hours_ago=4,
                issue_number=10,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/10",
                pr_hours_ago=2,
                acu_cost=1.8,
            ),
            RemediationStatus.PR_OPENED,
        ),
        (
            dict(
                slug="requests-bump",
                finding=_dep_finding(
                    rule="CVE-2025-22222",
                    pkg="requests",
                    installed="2.28.0",
                    fixed=["2.32.0"],
                    severity=Severity.HIGH,
                    cvss=7.8,
                ),
                hours_ago=60,
                issue_number=11,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/11",
                pr_hours_ago=52,
                acu_cost=2.6,
            ),
            RemediationStatus.PR_OPENED,
        ),
        # --- In-progress, PR not yet opened
        (
            dict(
                slug="subprocess-shell",
                finding=_sast_finding(
                    rule="B602",
                    file_path="superset/utils/shell.py",
                    line=19,
                    severity=Severity.HIGH,
                    title="subprocess call with shell=True",
                ),
                hours_ago=1,
                issue_number=12,
                acu_cost=0.8,
            ),
            RemediationStatus.SESSION_RUNNING,
        ),
        # --- Feedback loop: verifier pushed back, Devin iterating
        (
            dict(
                slug="jinja-autoescape",
                finding=_sast_finding(
                    rule="B701",
                    file_path="superset/templates/renderer.py",
                    line=55,
                    severity=Severity.HIGH,
                    title="Jinja2 autoescape disabled",
                ),
                hours_ago=6,
                issue_number=13,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/13",
                pr_hours_ago=3,
                acu_cost=2.2,
            ),
            RemediationStatus.VERIFICATION_FAILED,
        ),
        # --- Honest failures: one session aborted, one human-merged before re-scan
        (
            dict(
                slug="lxml-legacy",
                finding=_dep_finding(
                    rule="CVE-2024-55555",
                    pkg="lxml",
                    installed="3.8.0",
                    fixed=[],
                    severity=Severity.HIGH,
                    cvss=7.2,
                ),
                hours_ago=72,
                issue_number=14,
                acu_cost=1.1,
            ),
            RemediationStatus.FAILED,
        ),
        (
            dict(
                slug="django-pin",
                finding=_dep_finding(
                    rule="CVE-2025-33333",
                    pkg="django",
                    installed="3.2.0",
                    fixed=["3.2.25"],
                    severity=Severity.HIGH,
                    cvss=7.0,
                ),
                hours_ago=96,
                issue_number=15,
                pr_url=f"https://github.com/{TARGET_REPO}/pull/15",
                pr_hours_ago=90,
                acu_cost=3.0,
                resolved=True,
            ),
            RemediationStatus.MERGED_UNVERIFIED,
        ),
    ]
    for kwargs, status in plan:
        _seed(store, status=status, **kwargs)
    return [(kw["slug"], status.value) for kw, status in plan]


def reset_demo_rows(store: Store) -> int:
    """Delete only rows this script seeded (identified by dedupe_key prefix)
    so users' real pipeline-created rows are left untouched on a rerun."""
    like = DEMO_KEY_PREFIX + "%"
    with store._conn() as c:
        cur = c.execute(
            "DELETE FROM remediations WHERE dedupe_key LIKE ?", (like,)
        )
        c.execute("DELETE FROM events WHERE dedupe_key LIKE ?", (like,))
        return cur.rowcount


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--db",
        default=os.environ.get("ORCHESTRATOR_DB_PATH", "orchestrator.db"),
        help=(
            "Path to the SQLite DB file. Defaults to $ORCHESTRATOR_DB_PATH "
            "(set to /data/orchestrator.db inside the container)."
        ),
    )
    p.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing demo-seed rows before seeding",
    )
    args = p.parse_args()

    store = Store(args.db)
    if args.reset:
        removed = reset_demo_rows(store)
        print(f"reset: removed {removed} demo-seed row(s) from {args.db}")

    seeded = seed_all(store)
    print(f"seeded {len(seeded)} demo rows into {args.db}:")
    for slug, status in seeded:
        print(f"  - {DEMO_KEY_PREFIX}{slug:22s} -> {status}")
    print("\nOpen http://localhost:8080/dashboard to verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
