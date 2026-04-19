"""Pydantic schemas used by the orchestrator."""
from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from .time_utils import now_utc


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_cvss(cls, cvss: float | None) -> Severity:
        if cvss is None:
            return cls.MEDIUM
        if cvss >= 9.0:
            return cls.CRITICAL
        if cvss >= 7.0:
            return cls.HIGH
        if cvss >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


class FindingKind(StrEnum):
    DEP_CVE = "dep_cve"          # dependency vulnerability (pip-audit, npm audit, OSV)
    SAST = "sast"                # static analysis (bandit, semgrep, etc.)


class Finding(BaseModel):
    """Normalized finding that the orchestrator reasons about.

    The same schema is used whether the source is pip-audit, npm audit, bandit,
    or a simulated POST from scripts/simulate.sh.
    """

    # Required identity
    kind: FindingKind
    repo: str = Field(..., description="owner/repo the finding is in")
    rule_id: str = Field(..., description="CVE-XXXX, PYSEC-..., B324, S506, etc.")
    title: str

    # Severity
    severity: Severity
    cvss: float | None = None

    # Dependency-scoped fields
    package_ecosystem: str | None = None   # "PyPI", "npm", ...
    package_name: str | None = None
    installed_version: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    manifest_path: str | None = None       # requirements/base.txt, package.json, ...

    # SAST-scoped fields
    file_path: str | None = None
    line: int | None = None
    code_excerpt: str | None = None

    # Extra human context
    description: str | None = None
    advisory_url: str | None = None
    scanner: str = Field(..., description="pip-audit|bandit|semgrep|npm-audit|osv-scanner|manual")
    scanned_at: datetime = Field(default_factory=now_utc)

    def dedupe_key(self) -> str:
        """Stable hash used for idempotency.

        For a dep CVE: (repo, package, rule_id).
        For SAST: (repo, rule_id, file_path). We intentionally do NOT include
        line numbers, because small edits would otherwise bypass dedupe.
        """
        if self.kind == FindingKind.DEP_CVE:
            parts = [self.repo, (self.package_name or "").lower(), self.rule_id]
        else:
            parts = [self.repo, self.rule_id, self.file_path or ""]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def human_title(self) -> str:
        if self.kind == FindingKind.DEP_CVE and self.package_name:
            fixed = ", ".join(self.fixed_versions) if self.fixed_versions else "no fix yet"
            return f"[{self.severity.value}] {self.rule_id} in {self.package_name} {self.installed_version} (fixed: {fixed})"
        if self.kind == FindingKind.SAST:
            loc = f"{self.file_path}:{self.line}" if self.file_path else ""
            return f"[{self.severity.value}] {self.rule_id} ({self.title}) at {loc}"
        return f"[{self.severity.value}] {self.rule_id}: {self.title}"


class IngestRequest(BaseModel):
    """Payload POSTed to /ingest from scanners."""

    source: str = Field(..., description="identifier for the scan run, e.g. github-actions:run-42")
    findings: list[Finding]


class RemediationStatus(StrEnum):
    DEDUPED = "deduped"                # skipped: already tracked
    FILTERED = "filtered"              # skipped: below severity threshold
    ROUTED_BUMP_PR = "routed_bump_pr"  # opened a direct bump PR
    DISPATCHED = "dispatched"          # Devin session launched
    SESSION_RUNNING = "session_running"
    PR_OPENED = "pr_opened"
    VERIFIED_FIXED = "verified_fixed"
    VERIFICATION_FAILED = "verification_failed"
    RESOLVED = "resolved"
    FAILED = "failed"


class IngestResult(BaseModel):
    dedupe_key: str
    status: RemediationStatus
    reason: str | None = None
    issue_url: str | None = None
    session_id: str | None = None
    session_url: str | None = None
    pr_url: str | None = None


class IngestResponse(BaseModel):
    received: int
    results: list[IngestResult]


class RemediationRecord(BaseModel):
    """Database row shape."""

    dedupe_key: str
    finding: Finding
    status: RemediationStatus
    issue_number: int | None = None
    issue_url: str | None = None
    session_id: str | None = None
    session_url: str | None = None
    pr_url: str | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


class Stats(BaseModel):
    """Aggregate metrics served at /stats and rendered on /dashboard."""

    total_findings: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    active_sessions: int
    dedupe_hits: int
    prs_opened: int
    prs_merged: int
    verified_fixed: int
    verification_failed: int
    median_mttr_seconds: float | None
    p90_mttr_seconds: float | None
    success_rate: float | None
