"""Aggregate metrics for the /stats and /dashboard endpoints."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime

from .config import Settings
from .db import Store
from .models import RemediationRecord, RemediationStatus, RulePerformance, Stats
from .time_utils import now_utc


def compute_stats(store: Store, settings: Settings | None = None) -> Stats:
    records = store.list_all()

    by_status: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    active_sessions = 0
    dedupe_hits = 0
    prs_opened = 0
    verified_fixed = 0
    verification_failed = 0
    needs_attention = 0
    total_acus = 0.0
    mttrs: list[float] = []

    now = now_utc()
    warn_hours = settings.stale_pr_warn_hours if settings else 24.0
    baseline_hours = settings.baseline_hours_per_finding if settings else 2.0
    usd_rate = settings.acu_usd_rate if settings else 0.0

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
        if _is_needs_attention(r, warn_hours, now):
            needs_attention += 1
        if r.acu_cost is not None:
            total_acus += r.acu_cost
        if r.resolved_at:
            mttrs.append((r.resolved_at - r.created_at).total_seconds())

    median_mttr = statistics.median(mttrs) if mttrs else None
    p90_mttr = _percentile(mttrs, 0.9) if mttrs else None

    terminal_failure = (
        verification_failed
        + by_status.get(RemediationStatus.FAILED.value, 0)
        + by_status.get(RemediationStatus.HUMAN_REJECTED.value, 0)
    )
    total_terminal = verified_fixed + terminal_failure
    success_rate = verified_fixed / total_terminal if total_terminal > 0 else None

    acu_per_fix = total_acus / verified_fixed if verified_fixed else None
    total_usd = total_acus * usd_rate if usd_rate > 0 else None
    usd_per_fix = (
        (acu_per_fix * usd_rate) if (acu_per_fix is not None and usd_rate > 0) else None
    )

    triaged = sum(
        by_status.get(s.value, 0)
        for s in (
            RemediationStatus.VERIFIED_FIXED,
            RemediationStatus.MERGED_UNVERIFIED,
            RemediationStatus.HUMAN_REJECTED,
            RemediationStatus.DEDUPED,
            RemediationStatus.FILTERED,
        )
    )
    hours_saved = triaged * baseline_hours

    by_rule = _compute_by_rule(records)

    return Stats(
        total_findings=len(records),
        by_status=dict(by_status),
        by_severity=dict(by_severity),
        active_sessions=active_sessions,
        dedupe_hits=dedupe_hits,
        prs_opened=prs_opened,
        verified_fixed=verified_fixed,
        verification_failed=verification_failed,
        needs_attention=needs_attention,
        median_mttr_seconds=median_mttr,
        p90_mttr_seconds=p90_mttr,
        success_rate=success_rate,
        total_acus_spent=round(total_acus, 2),
        acu_per_fix=round(acu_per_fix, 2) if acu_per_fix is not None else None,
        total_usd_spent=round(total_usd, 2) if total_usd is not None else None,
        usd_per_fix=round(usd_per_fix, 2) if usd_per_fix is not None else None,
        hours_saved_estimate=round(hours_saved, 1),
        by_rule=by_rule,
    )


def _compute_by_rule(records: list[RemediationRecord]) -> list[RulePerformance]:
    """Aggregate records by rule_id so the dashboard can surface which rules
    Devin handles well vs struggles on."""
    buckets: dict[str, list[RemediationRecord]] = defaultdict(list)
    for r in records:
        buckets[r.finding.rule_id].append(r)

    out: list[RulePerformance] = []
    for rule_id, rows in buckets.items():
        verified = sum(1 for r in rows if r.status == RemediationStatus.VERIFIED_FIXED)
        failed = sum(
            1
            for r in rows
            if r.status
            in {
                RemediationStatus.VERIFICATION_FAILED,
                RemediationStatus.FAILED,
                RemediationStatus.HUMAN_REJECTED,
            }
        )
        in_flight = sum(
            1
            for r in rows
            if r.status
            in {
                RemediationStatus.DISPATCHED,
                RemediationStatus.SESSION_RUNNING,
                RemediationStatus.PR_OPENED,
                RemediationStatus.NEEDS_ATTENTION,
            }
        )
        total_terminal = verified + failed
        success_rate = verified / total_terminal if total_terminal > 0 else None
        mttrs = [
            (r.resolved_at - r.created_at).total_seconds()
            for r in rows
            if r.resolved_at
        ]
        median = statistics.median(mttrs) if mttrs else None
        costs = [r.acu_cost for r in rows if r.acu_cost is not None]
        avg_cost = sum(costs) / len(costs) if costs else None
        out.append(
            RulePerformance(
                rule_id=rule_id,
                total=len(rows),
                verified_fixed=verified,
                failed=failed,
                in_flight=in_flight,
                success_rate=success_rate,
                median_mttr_seconds=median,
                avg_acu_cost=round(avg_cost, 2) if avg_cost is not None else None,
            )
        )
    # Surface the highest-volume rules first; ties broken by success rate ascending
    # so rules Devin is struggling on float up. Rules without a terminal row
    # yet (success_rate is None) sort last so they don't crowd the top.
    out.sort(
        key=lambda r: (-r.total, r.success_rate if r.success_rate is not None else 2.0)
    )
    return out


def _is_needs_attention(
    rec: RemediationRecord, warn_hours: float, now: datetime
) -> bool:
    """Shared definition used by both /stats and the Prometheus gauge.

    An operator should see the same number in the dashboard card and in
    alertmanager — flagging one place and missing the other is worse than
    flagging neither.
    """
    if rec.status == RemediationStatus.NEEDS_ATTENTION:
        return True
    return (
        rec.status == RemediationStatus.PR_OPENED
        and rec.pr_age_hours(now) >= warn_hours
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
