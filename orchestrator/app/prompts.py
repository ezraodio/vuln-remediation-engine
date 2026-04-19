"""Templates for the prompt Devin receives.

A good prompt is the single biggest lever on Devin's success rate. We include:
  - unambiguous problem statement (one CVE / SAST rule)
  - acceptance criteria (scanner passes, CI passes, no unrelated changes)
  - links to the advisory / docs
  - a minimal hint at where the issue lives
  - strict output format (open a PR against main)
"""
from __future__ import annotations

from .models import Finding, FindingKind

_ACCEPTANCE_CRITERIA = """\
Acceptance criteria (ALL must hold before opening the PR):
  1. The specific finding above is no longer reported by the scanner on your branch.
  2. Existing tests still pass. Run the relevant subset locally.
  3. The PR contains only changes necessary to remediate this finding. No
     drive-by refactors, no unrelated version bumps, no formatting churn
     outside the files you actually changed.
  4. Include a one-sentence summary in the PR description explaining the root
     cause and your fix, and a short "How I verified" section.
  5. Reference the tracking issue by number in the PR body (e.g. "Closes #N").
"""


def build_prompt(finding: Finding, *, target_repo: str, issue_number: int | None) -> str:
    if finding.kind == FindingKind.DEP_CVE:
        return _dep_cve_prompt(finding, target_repo, issue_number)
    return _sast_prompt(finding, target_repo, issue_number)


def _dep_cve_prompt(finding: Finding, target_repo: str, issue_number: int | None) -> str:
    fixed = ", ".join(finding.fixed_versions) if finding.fixed_versions else "no patched version published yet"
    advisory = finding.advisory_url or "(no advisory URL provided)"
    issue_ref = f"Tracking issue: #{issue_number}" if issue_number else ""
    manifest = finding.manifest_path or "requirements/*.txt or package.json (pick the right one)"
    return f"""\
You are remediating a dependency vulnerability in the repository `{target_repo}`.

## Vulnerability
  - Advisory: {finding.rule_id}
  - Severity: {finding.severity.value}{" (CVSS " + str(finding.cvss) + ")" if finding.cvss else ""}
  - Package: {finding.package_name} (ecosystem: {finding.package_ecosystem})
  - Installed version: {finding.installed_version}
  - Fixed in: {fixed}
  - Manifest: {manifest}
  - Advisory URL: {advisory}

## Description
{finding.description or "(no description provided)"}

## What to do
  1. Clone `{target_repo}` and check out a new branch from `main` named
     `devin/remediate-{finding.rule_id.lower()}`.
  2. Determine the minimum safe upgrade for `{finding.package_name}` that
     resolves {finding.rule_id}. Prefer the lowest fixed version to minimize
     blast radius.
  3. If the upgrade has breaking API changes that affect this codebase, make
     the smallest possible code changes to keep the code working. Search for
     usages first with grep.
  4. If and only if no patched version exists yet, implement a mitigation in
     first-party code (input validation, feature flag, disabled code path)
     and clearly call that out in the PR.
  5. Re-run `pip-audit -r {manifest}` (or the equivalent for this ecosystem).
     The listed advisory must no longer appear.
  6. Run the relevant test suite for the affected areas.
  7. Open a pull request against `main` of `{target_repo}`.

{_ACCEPTANCE_CRITERIA}

{issue_ref}
"""


def _sast_prompt(finding: Finding, target_repo: str, issue_number: int | None) -> str:
    issue_ref = f"Tracking issue: #{issue_number}" if issue_number else ""
    loc = f"{finding.file_path}:{finding.line}" if finding.file_path else "(unknown)"
    return f"""\
You are remediating a static-analysis finding in the repository `{target_repo}`.

## Finding
  - Rule: {finding.rule_id} ({finding.title})
  - Severity: {finding.severity.value}
  - Scanner: {finding.scanner}
  - Location: {loc}

## Code excerpt
```
{finding.code_excerpt or "(no excerpt provided — read the file to understand context)"}
```

## Description
{finding.description or "(no description)"}

## What to do
  1. Clone `{target_repo}` and check out a new branch from `main` named
     `devin/remediate-{finding.rule_id.lower()}-{_slug(finding.file_path)}`.
  2. Read the file at `{loc}` and the immediate callers / call sites. Decide
     whether the finding is:
        (a) a true positive requiring a code change, or
        (b) a false positive where the correct fix is a narrowly-scoped
            `# nosec` / `# noqa` annotation with a one-line justification.
     Do NOT silence the finding unless you are confident it is a false positive.
  3. Apply the smallest code change that removes the finding without changing
     externally observable behavior. Do the analogous fix at any other
     occurrences in the repo (use grep).
  4. Re-run the scanner (e.g. `bandit -r <pkg> -ll`). The listed finding
     must no longer appear.
  5. Run the tests that touch the files you changed.
  6. Open a pull request against `main` of `{target_repo}`.

{_ACCEPTANCE_CRITERIA}

{issue_ref}
"""


def _slug(path: str | None) -> str:
    if not path:
        return "anon"
    return (
        path.replace("/", "-").replace(".", "-").replace("_", "-").lower()[-40:]
    )
