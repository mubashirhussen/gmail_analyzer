"""Lightweight performance sampler (Module 11).

Maintains an EWMA + p95 approximation of HTTP request latency in-process
so `/api/v1/platform/status` can report a real-time picture without
requiring Prometheus scraping. Not a replacement for the metrics service.
"""
from __future__ import annotations

import bisect
import threading
from collections import deque
from typing import Deque


class PerformanceService:
    def __init__(self, window: int = 512) -> None:
        self._samples: Deque[float] = deque(maxlen=window)
        self._lock = threading.Lock()
        self._ewma_ms = 0.0
        self._alpha = 0.2

    def observe_ms(self, value_ms: float) -> None:
        with self._lock:
            self._samples.append(value_ms)
            self._ewma_ms = (
                value_ms if not self._ewma_ms
                else self._alpha * value_ms + (1 - self._alpha) * self._ewma_ms
            )

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            if not self._samples:
                return {"count": 0, "ewma_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
            xs = sorted(self._samples)
            return {
                "count": len(xs),
                "ewma_ms": round(self._ewma_ms, 2),
                "p50_ms": round(xs[len(xs) // 2], 2),
                "p95_ms": round(xs[min(len(xs) - 1, bisect.bisect_left(xs, xs[-1]) or int(len(xs) * 0.95))], 2),
                "max_ms": round(xs[-1], 2),
            }


performance_service = PerformanceService()
