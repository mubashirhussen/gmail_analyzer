"""Module 11 — hardening layer smoke tests."""
from __future__ import annotations

import asyncio

import pytest

from app.services.platform.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.services.platform.performance_service import PerformanceService
from app.services.platform.retry import retry_async


def test_performance_service_snapshot() -> None:
    svc = PerformanceService(window=8)
    for v in (10.0, 20.0, 30.0, 40.0, 50.0):
        svc.observe_ms(v)
    snap = svc.snapshot()
    assert snap["count"] == 5
    assert snap["max_ms"] == 50.0
    assert snap["p50_ms"] > 0


def test_circuit_breaker_opens_after_threshold() -> None:
    cb = CircuitBreaker(name="test", failure_threshold=2, recovery_time_s=60)

    async def boom() -> None:
        raise RuntimeError("nope")

    async def go() -> None:
        for _ in range(2):
            with pytest.raises(RuntimeError):
                await cb.call(boom)
        with pytest.raises(CircuitOpenError):
            await cb.call(boom)

    asyncio.run(go())


def test_retry_async_eventually_succeeds() -> None:
    calls = {"n": 0}

    async def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("still flaky")
        return "ok"

    result = asyncio.run(retry_async(flaky, attempts=5, base_delay=0.01, name="unit"))
    assert result == "ok"
    assert calls["n"] == 3
