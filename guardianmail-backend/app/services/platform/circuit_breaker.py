"""In-memory circuit breaker for Module 11.

Protects outbound calls (third-party APIs) from cascading failure. Not
distributed — each worker keeps its own state, which is acceptable for
protecting a single process from wasting resources on a failing dependency.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, TypeVar

from app.services.platform.metrics_service import metrics_service

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """Raised when the circuit is open and a call is short-circuited."""


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 5
    recovery_time_s: float = 30.0
    _state: CircuitState = CircuitState.CLOSED
    _failures: int = 0
    _opened_at: float = 0.0
    _lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _emit(self) -> None:
        code = {CircuitState.CLOSED: 0, CircuitState.HALF_OPEN: 1, CircuitState.OPEN: 2}[self._state]
        try:
            metrics_service.circuit_state.labels(name=self.name).set(code)
        except Exception:  # noqa: BLE001
            pass

    async def call(self, fn: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        async with self._get_lock():
            if self._state is CircuitState.OPEN:
                if (time.time() - self._opened_at) >= self.recovery_time_s:
                    self._state = CircuitState.HALF_OPEN
                    self._emit()
                else:
                    raise CircuitOpenError(f"circuit '{self.name}' is open")
        try:
            result = await fn(*args, **kwargs)
        except Exception:
            async with self._get_lock():
                self._failures += 1
                if self._failures >= self.failure_threshold or self._state is CircuitState.HALF_OPEN:
                    self._state = CircuitState.OPEN
                    self._opened_at = time.time()
                    self._emit()
            raise
        else:
            async with self._get_lock():
                self._failures = 0
                self._state = CircuitState.CLOSED
                self._emit()
            return result
