"""Timezone-aware current-time helper.

Centralized so every timestamp in the orchestrator is consistent and
timezone-aware. `datetime.utcnow()` is deprecated in Python 3.12+.
"""
from __future__ import annotations

from datetime import UTC, datetime


def now_utc() -> datetime:
    """Return the current UTC time with tzinfo attached."""
    return datetime.now(UTC)
