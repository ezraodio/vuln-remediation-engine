"""Routing decision: dispatch to Devin, or skip."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, FindingKind, Severity


@dataclass
class RoutingDecision:
    action: str          # "dispatch_devin" | "skip"
    reason: str


class Router:
    """Decide what to do with a finding.

    SAST findings always go to Devin — they need judgment (true-positive
    detection, narrow suppression vs. code rewrite, etc.).

    Dep CVEs go to Devin unless they fall below the severity/CVSS floor, in
    which case they are skipped entirely (Dependabot and the next scan cycle
    will cover those).
    """

    def __init__(self, *, min_severity: Severity, min_cvss: float):
        self.min_severity = min_severity
        self.min_cvss = min_cvss

    def decide(self, finding: Finding) -> RoutingDecision:
        below_sev = finding.severity.rank() < self.min_severity.rank()
        below_cvss = finding.cvss is None or finding.cvss < self.min_cvss
        if below_sev and below_cvss:
            return RoutingDecision(
                action="skip",
                reason=f"severity {finding.severity.value} below threshold {self.min_severity.value}",
            )

        if finding.kind == FindingKind.SAST:
            return RoutingDecision(
                action="dispatch_devin",
                reason="SAST findings require code-change judgment",
            )

        if finding.kind == FindingKind.DEP_CVE:
            if not finding.fixed_versions:
                return RoutingDecision(
                    action="dispatch_devin",
                    reason="No patched version published — need a code-level mitigation",
                )
            return RoutingDecision(
                action="dispatch_devin",
                reason="Dependency upgrade may require code changes",
            )

        # Fail loudly if a new FindingKind is added without a routing branch;
        # silently dispatching would hide a misuse until prod.
        raise NotImplementedError(f"unhandled FindingKind: {finding.kind!r}")
