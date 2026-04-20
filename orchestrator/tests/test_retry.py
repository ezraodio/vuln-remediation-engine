"""Exercise the transient-failure retry paths in app.retry."""
from __future__ import annotations

import httpx
import pytest

from app.retry import with_retry


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


async def test_retries_on_5xx_then_succeeds(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _noop_sleep)
    responses = iter([_Response(503), _Response(503), _Response(200)])

    async def fn():
        return next(responses)

    r = await with_retry(fn, attempts=3, base_delay=0.0, op="test")
    assert r.status_code == 200


async def test_returns_last_response_when_attempts_exhausted(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _noop_sleep)
    responses = iter([_Response(503), _Response(503), _Response(503)])

    async def fn():
        return next(responses)

    r = await with_retry(fn, attempts=3, base_delay=0.0, op="test")
    assert r.status_code == 503


async def test_retries_on_network_error_then_succeeds(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _noop_sleep)
    calls = {"n": 0}

    async def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom")
        return _Response(200)

    r = await with_retry(fn, attempts=3, base_delay=0.0, op="test")
    assert r.status_code == 200
    assert calls["n"] == 3


async def test_reraises_network_error_when_attempts_exhausted(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _noop_sleep)

    async def fn():
        raise httpx.ReadError("boom")

    with pytest.raises(httpx.ReadError):
        await with_retry(fn, attempts=2, base_delay=0.0, op="test")


async def test_does_not_retry_on_non_retryable_status(monkeypatch):
    monkeypatch.setattr("asyncio.sleep", _noop_sleep)
    calls = {"n": 0}

    async def fn():
        calls["n"] += 1
        return _Response(404)

    r = await with_retry(fn, attempts=3, base_delay=0.0, op="test")
    assert r.status_code == 404
    assert calls["n"] == 1


async def _noop_sleep(_delay: float) -> None:
    return None
