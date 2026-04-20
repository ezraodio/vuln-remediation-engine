"""Prometheus metrics for the orchestrator.

Exposed at ``/metrics`` by ``main.py``. Counters and histograms cover the
three operational moments an on-call engineer needs to alert on: findings
ingested, Devin sessions dispatched (and their failure rate), and
verification outcomes. Keeping metric names stable across releases so
Grafana dashboards and alert rules don't break.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# Increments once per finding the orchestrator accepts at /ingest — the
# input-side volume signal. Pair with ``findings_dispatched_total`` to
# compute dedupe / filter rates.
findings_ingested = Counter(
    "vrm_findings_ingested_total",
    "Findings accepted at /ingest, labelled by scanner kind and severity.",
    labelnames=("kind", "severity"),
)

findings_dispatched = Counter(
    "vrm_findings_dispatched_total",
    "Findings that actually resulted in a Devin session being created.",
    labelnames=("kind", "severity"),
)

findings_deduped = Counter(
    "vrm_findings_deduped_total",
    "Findings that short-circuited via one of the three dedupe layers.",
    labelnames=("layer",),
)

findings_filtered = Counter(
    "vrm_findings_filtered_total",
    "Findings dropped by the severity/CVSS router or by DRY_RUN.",
    labelnames=("reason",),
)

dispatch_failures = Counter(
    "vrm_dispatch_failures_total",
    "Devin session dispatch failures — primary SLO alert target.",
    labelnames=("scanner",),
)

verify_outcomes = Counter(
    "vrm_verify_outcomes_total",
    "Verification reports received, by outcome.",
    labelnames=("outcome",),
)

verify_latency_seconds = Histogram(
    "vrm_verify_latency_seconds",
    "Time from ingest to verification outcome.",
    buckets=(60, 300, 600, 1800, 3600, 7200, 21600, 86400),
)

mttr_seconds = Histogram(
    "vrm_mttr_seconds",
    "Time from ingest to VERIFIED_FIXED.",
    buckets=(300, 600, 1800, 3600, 7200, 21600, 86400, 172800),
)

acu_cost_per_session = Histogram(
    "vrm_acu_cost_per_session",
    "ACUs consumed per Devin session.",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 25, 50, 100),
)

active_sessions = Gauge(
    "vrm_active_sessions",
    "Number of remediations currently in DISPATCHED or SESSION_RUNNING.",
)

needs_attention_gauge = Gauge(
    "vrm_needs_attention",
    "Number of remediations flagged as NEEDS_ATTENTION — page on-call.",
)

stale_prs_gauge = Gauge(
    "vrm_stale_prs",
    "PRs open longer than STALE_PR_WARN_HOURS but not yet NEEDS_ATTENTION.",
)
