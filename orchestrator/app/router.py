"""Routing decision: does this finding go to Devin, get a direct bump PR, or get skipped?"""
from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from .models import Finding, FindingKind, Severity


@dataclass
class RoutingDecision:
    action: str          # "dispatch_devin" | "open_bump_pr" | "skip"
    reason: str
    bump_target: str | None = None


class Router:
    """Decide what to do with a finding.

    Strategy options (set via settings.bump_strategy):
      - "dispatch"  : always use Devin for anything above threshold.
      - "bump_pr"   : for dep CVEs with a clean single-package bump, open
                      a direct version-bump PR (cheaper, faster).
      - "skip"      : for trivial dep CVEs, skip and let Dependabot handle it.

    SAST findings always go to Devin — they need judgment.
    """

    def __init__(self, *, min_severity: Severity, min_cvss: float, bump_strategy: str):
        self.min_severity = min_severity
        self.min_cvss = min_cvss
        self.bump_strategy = bump_strategy

    def decide(self, finding: Finding) -> RoutingDecision:
        # 1) Severity filter: skip if under severity floor AND CVSS floor.
        below_sev = finding.severity.rank() < self.min_severity.rank()
        below_cvss = finding.cvss is None or finding.cvss < self.min_cvss
        if below_sev and below_cvss:
            return RoutingDecision(
                action="skip",
                reason=f"severity {finding.severity.value} below threshold {self.min_severity.value}",
            )

        # 2) SAST → always Devin
        if finding.kind == FindingKind.SAST:
            return RoutingDecision(
                action="dispatch_devin",
                reason="SAST findings require code-change judgment",
            )

        # 3) Dep CVE routing
        if finding.kind == FindingKind.DEP_CVE:
            if not finding.fixed_versions:
                return RoutingDecision(
                    action="dispatch_devin",
                    reason="No patched version published — need a code-level mitigation",
                )
            target = _lowest_fixed_version(finding)
            if self.bump_strategy == "skip":
                return RoutingDecision(
                    action="skip",
                    reason="bump_strategy=skip: delegating to Dependabot",
                )
            if self.bump_strategy == "bump_pr" and _is_trivial_bump(finding, target):
                return RoutingDecision(
                    action="open_bump_pr",
                    reason=f"Patch-level bump to {target}, no expected breaking changes",
                    bump_target=target,
                )
            # Default: dispatch
            return RoutingDecision(
                action="dispatch_devin",
                reason="Upgrade may require code changes (major bump or non-patch)",
                bump_target=target,
            )

        return RoutingDecision(action="dispatch_devin", reason="default")


def _lowest_fixed_version(finding: Finding) -> str:
    best: Version | None = None
    best_raw: str | None = None
    for v in finding.fixed_versions:
        try:
            parsed = Version(v)
        except InvalidVersion:
            continue
        if best is None or parsed < best:
            best, best_raw = parsed, v
    return best_raw or (finding.fixed_versions[0] if finding.fixed_versions else "")


def _is_trivial_bump(finding: Finding, target: str) -> bool:
    """Heuristic: is this a patch-level bump with no major change?"""
    if not finding.installed_version or not target:
        return False
    try:
        cur = Version(finding.installed_version)
        new = Version(target)
    except InvalidVersion:
        return False
    # Same major+minor, only patch changes → trivial.
    return cur.release[:2] == new.release[:2]
