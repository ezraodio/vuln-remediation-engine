"""Small retry helper for HTTP calls to external services.

Retries on network errors (connect/read/timeout) and 5xx/429 responses,
with jittered exponential backoff. Deliberately narrow: only wraps
idempotent calls — callers decide whether a given request is safe to
retry (GETs always are; POSTs only if the API guarantees idempotency,
e.g. Devin `create_session` with `idempotent=True`).
"""
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

import httpx

from .logging_config import get_logger

log = get_logger("retry")

T = TypeVar("T")

_RETRY_STATUSES = {429, 500, 502, 503, 504}


async def with_retry(
    fn: Callable[[], Awaitable[httpx.Response]],
    *,
    attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 4.0,
    op: str = "http",
) -> httpx.Response:
    """Call `fn()` up to `attempts` times, retrying on transient failures.

    Returns the first non-retryable response (success or hard 4xx). Raises
    the last exception if all attempts error out at the network layer.
    """
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            r = await fn()
        except (httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.TimeoutException) as e:
            last_exc = e
            if attempt == attempts:
                log.warning("retry_exhausted_network", op=op, attempts=attempts, err=str(e))
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1))) + random.uniform(0, 0.1)
            log.info("retry_network", op=op, attempt=attempt, delay=round(delay, 3), err=str(e))
            await asyncio.sleep(delay)
            continue
        if r.status_code not in _RETRY_STATUSES or attempt == attempts:
            return r
        delay = min(max_delay, base_delay * (2 ** (attempt - 1))) + random.uniform(0, 0.1)
        log.info(
            "retry_status",
            op=op,
            attempt=attempt,
            status=r.status_code,
            delay=round(delay, 3),
        )
        await asyncio.sleep(delay)
    # Unreachable: the loop either returns or raises.
    assert last_exc is None
    raise RuntimeError("unreachable")
