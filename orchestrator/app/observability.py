"""Aggregate metrics for the /stats and /dashboard endpoints."""
from __future__ import annotations

import statistics
from collections import Counter

from .db import Store
from .models import RemediationStatus, Stats


def compute_stats(store: Store) -> Stats:
    records = store.list_all()

    by_status: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    active_sessions = 0
    dedupe_hits = 0
    prs_opened = 0
    prs_merged = 0
    verified_fixed = 0
    verification_failed = 0
    mttrs: list[float] = []

    for r in records:
        by_status[r.status.value] += 1
        by_severity[r.finding.severity.value] += 1
        if r.status == RemediationStatus.DEDUPED:
            dedupe_hits += 1
        if r.status in {
            RemediationStatus.DISPATCHED,
            RemediationStatus.SESSION_RUNNING,
        }:
            active_sessions += 1
        if r.pr_url:
            prs_opened += 1
        if r.status == RemediationStatus.VERIFIED_FIXED:
            verified_fixed += 1
        if r.status == RemediationStatus.VERIFICATION_FAILED:
            verification_failed += 1
        if r.status == RemediationStatus.RESOLVED:
            prs_merged += 1
        if r.resolved_at:
            mttrs.append((r.resolved_at - r.created_at).total_seconds())

    median_mttr = statistics.median(mttrs) if mttrs else None
    p90_mttr = _percentile(mttrs, 0.9) if mttrs else None

    terminal_success = verified_fixed + prs_merged
    terminal_failure = verification_failed + by_status.get("failed", 0)
    total_terminal = terminal_success + terminal_failure
    success_rate = terminal_success / total_terminal if total_terminal > 0 else None

    return Stats(
        total_findings=len(records),
        by_status=dict(by_status),
        by_severity=dict(by_severity),
        active_sessions=active_sessions,
        dedupe_hits=dedupe_hits,
        prs_opened=prs_opened,
        prs_merged=prs_merged,
        verified_fixed=verified_fixed,
        verification_failed=verification_failed,
        median_mttr_seconds=median_mttr,
        p90_mttr_seconds=p90_mttr,
        success_rate=success_rate,
    )


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)
