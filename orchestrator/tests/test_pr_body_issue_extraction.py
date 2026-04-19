"""Regression test for the PR-body closing-keyword extractor used by
scanner/verify-devin-pr.yml.

The workflow extracts the tracking-issue number from Devin's PR body so it
can load orchestrator metadata (rule_id, file_path, package_name) and
filter the branch's scanner output down to the *specific* finding we asked
Devin to remediate. Using the first bare `#N` in the body is fragile:
Devin often references other issues in discussion before the "Closes #N"
line. This test codifies the preference order.

The regex itself is duplicated inside the YAML; if you change either, keep
them in lock-step.
"""
from __future__ import annotations

import re

_CLOSING = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*#(\d+)",
    re.IGNORECASE,
)
_BARE = re.compile(r"#(\d+)")


def _extract(body: str) -> str | None:
    m = _CLOSING.search(body) or _BARE.search(body)
    return m.group(1) if m else None


def test_prefers_closes_over_earlier_bare_reference():
    body = "As discussed in #17, this PR closes #42."
    assert _extract(body) == "42"


def test_accepts_fixes_resolves_and_past_tense():
    assert _extract("Fixes #3") == "3"
    assert _extract("resolved #9") == "9"
    assert _extract("This closed #101.") == "101"
    assert _extract("fixed: #7") == "7"


def test_case_insensitive():
    assert _extract("CLOSES #12") == "12"
    assert _extract("Closes #12") == "12"


def test_falls_back_to_first_bare_reference():
    body = "See #5 for context."
    assert _extract(body) == "5"


def test_returns_none_when_no_reference():
    assert _extract("nothing in here") is None
    assert _extract("") is None


def test_ignores_hashes_inside_urls_and_anchors_by_falling_back():
    # Bare-# fallback is permissive; we accept this is imperfect. The
    # important assertion is that the *closing* keyword always wins when
    # present — so a PR body that links to a URL with #fragment but also
    # has "Closes #42" still picks 42.
    body = "See https://example.com/foo#bar — Closes #42."
    assert _extract(body) == "42"
