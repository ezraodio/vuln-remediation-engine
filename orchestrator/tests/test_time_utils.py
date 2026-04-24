"""Tests for the tiny time_utils module.

Centralizing time is essential for test determinism; these tests lock in the
contract (always tz-aware UTC) so a future refactor can't silently regress it.
"""
from __future__ import annotations

from datetime import UTC, timedelta

from app.time_utils import now_utc


def test_now_utc_is_timezone_aware():
    dt = now_utc()
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timedelta(0)
    assert dt.tzinfo is UTC


def test_now_utc_is_monotonic_nondecreasing():
    a = now_utc()
    b = now_utc()
    assert b >= a
