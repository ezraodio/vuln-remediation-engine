"""Aggregate metrics for the /stats and /dashboard endpoints."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from .config import Settings
from .db import Store
from .models import RemediationRecord, RemediationStatus, RulePerformance, Stats
from .time_utils import now_utc

_DEFAULT_WARN_HOURS = 24.0
_DEFAULT_BASELINE_HOURS = 2.0

_TRIAGED_STATUSES = frozenset(
    {
        RemediationStatus.VERIFIED_FIXED,
        RemediationStatus.MERGED_UNVERIFIED,
        RemediationStatus.HUMAN_REJECTED,
        RemediationStatus.DEDUPED,
        RemediationStatus.FILTERED,
    }
)

_ACTIVE_SESSION_STATUSES = frozenset(
    {RemediationStatus.DISPATCHED, RemediationStatus.SESSION_RUNNING}
)

_TERMINAL_FAILURE_STATUSES = frozenset(
    {
        RemediationStatus.VERIFICATION_FAILED,
        RemediationStatus.FAILED,
        RemediationStatus.HUMAN_REJECTED,
    }
)


@dataclass
class _Tally:
    """Running totals accumulated in a single pass over the remediation store.

    A dedicated struct (rather than a stack of local counters) keeps
    :func:`compute_stats` focused on deriving reportable metrics rather than
    on mutating state inside a long loop.
    """
    total: int = 0
    by_status: Counter[str] = field(default_factory=Counter)
    by_severity: Counter[str] = field(default_factory=Counter)
    active_sessions: int = 0
    dedupe_hits: int = 0
    prs_opened: int = 0
    verified_fixed: int = 0
    verification_failed: int = 0
    needs_attention: int = 0
    total_acus: float = 0.0
    mttrs: list[float] = field(default_factory=list)


def _tally_records(
    records: list[RemediationRecord], *, warn_hours: float, now: datetime
) -> _Tally:
    t = _Tally(total=len(records))
    for r in records:
        t.by_status[r.status.value] += 1
        t.by_severity[r.finding.severity.value] += 1
        if r.status == RemediationStatus.DEDUPED:
            t.dedupe_hits += 1
        if r.status in _ACTIVE_SESSION_STATUSES:
            t.active_sessions += 1
        if r.pr_url:
            t.prs_opened += 1
        if r.status == RemediationStatus.VERIFIED_FIXED:
            t.verified_fixed += 1
        if r.status == RemediationStatus.VERIFICATION_FAILED:
            t.verification_failed += 1
        if is_needs_attention(r, warn_hours, now):
            t.needs_attention += 1
        if r.acu_cost is not None:
            t.total_acus += r.acu_cost
        if r.resolved_at:
            t.mttrs.append((r.resolved_at - r.created_at).total_seconds())
    return t


def _derive_success_rate(t: _Tally) -> float | None:
    failed = sum(t.by_status.get(s.value, 0) for s in _TERMINAL_FAILURE_STATUSES)
    total_terminal = t.verified_fixed + failed
    if total_terminal == 0:
        return None
    return t.verified_fixed / total_terminal


def _derive_cost_metrics(
    t: _Tally, usd_rate: float
) -> tuple[float | None, float | None, float | None]:
    """Return ``(acu_per_fix, total_usd, usd_per_fix)``.

    USD metrics are ``None`` when ``usd_rate`` is zero because ACU-to-USD
    conversion depends on the caller's Devin plan; hardcoding a number
    would be misleading. Callers that do not supply a rate see ACUs only.
    """
    acu_per_fix = t.total_acus / t.verified_fixed if t.verified_fixed else None
    if usd_rate <= 0:
        return acu_per_fix, None, None
    total_usd = t.total_acus * usd_rate
    usd_per_fix = acu_per_fix * usd_rate if acu_per_fix is not None else None
    return acu_per_fix, total_usd, usd_per_fix


def compute_stats(store: Store, settings: Settings | None = None) -> Stats:
    records = store.list_all()
    warn_hours = settings.stale_pr_warn_hours if settings else _DEFAULT_WARN_HOURS
    baseline_hours = (
        settings.baseline_hours_per_finding if settings else _DEFAULT_BASELINE_HOURS
    )
    usd_rate = settings.acu_usd_rate if settings else 0.0

    t = _tally_records(records, warn_hours=warn_hours, now=now_utc())
    acu_per_fix, total_usd, usd_per_fix = _derive_cost_metrics(t, usd_rate)
    triaged = sum(t.by_status.get(s.value, 0) for s in _TRIAGED_STATUSES)

    return Stats(
        total_findings=t.total,
        by_status=dict(t.by_status),
        by_severity=dict(t.by_severity),
        active_sessions=t.active_sessions,
        dedupe_hits=t.dedupe_hits,
        prs_opened=t.prs_opened,
        verified_fixed=t.verified_fixed,
        verification_failed=t.verification_failed,
        needs_attention=t.needs_attention,
        median_mttr_seconds=statistics.median(t.mttrs) if t.mttrs else None,
        p90_mttr_seconds=_percentile(t.mttrs, 0.9) if t.mttrs else None,
        success_rate=_derive_success_rate(t),
        total_acus_spent=round(t.total_acus, 2),
        acu_per_fix=round(acu_per_fix, 2) if acu_per_fix is not None else None,
        total_usd_spent=round(total_usd, 2) if total_usd is not None else None,
        usd_per_fix=round(usd_per_fix, 2) if usd_per_fix is not None else None,
        hours_saved_estimate=round(triaged * baseline_hours, 1),
        by_rule=_compute_by_rule(records),
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


def is_stale_pr(
    rec: RemediationRecord, warn_hours: float, now: datetime | None = None
) -> bool:
    """A PR_OPENED record whose PR has aged past the warn threshold.

    Shared by the dashboard "stale" badge and the ``vrm_stale_prs`` Prometheus
    gauge so both surfaces agree on the same definition.
    """
    return (
        rec.status == RemediationStatus.PR_OPENED
        and rec.pr_age_hours(now) >= warn_hours
    )


def is_needs_attention(
    rec: RemediationRecord, warn_hours: float, now: datetime
) -> bool:
    """Shared definition used by both /stats and the Prometheus gauge.

    An operator should see the same number in the dashboard card and in
    alertmanager — flagging one place and missing the other is worse than
    flagging neither.
    """
    if rec.status == RemediationStatus.NEEDS_ATTENTION:
        return True
    return is_stale_pr(rec, warn_hours, now)


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
