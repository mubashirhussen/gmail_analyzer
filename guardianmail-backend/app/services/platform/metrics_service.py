"""Prometheus metrics facade for Module 11.

Reuses `prometheus_client` if installed (already used by Module 8's worker
hooks) and falls back to a tiny in-memory shim so the service is always
importable in tests. Exposes `render()` returning text/plain in Prometheus
exposition format.
"""
from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)

try:
    from prometheus_client import (CONTENT_TYPE_LATEST, CollectorRegistry,
                                   Counter, Gauge, Histogram, generate_latest)
    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"  # type: ignore

    class _Noop:
        def labels(self, *_a, **_kw): return self
        def inc(self, *_a, **_kw): return None
        def observe(self, *_a, **_kw): return None
        def set(self, *_a, **_kw): return None

    Counter = Gauge = Histogram = lambda *a, **kw: _Noop()  # type: ignore
    CollectorRegistry = object  # type: ignore


class MetricsService:
    """Owns the Prometheus registry for hardening-layer metrics."""

    def __init__(self) -> None:
        if _PROM:
            self.registry = CollectorRegistry(auto_describe=True)
            self.http_requests = Counter(
                "gm_http_requests_total",
                "Total HTTP requests",
                ["method", "route", "status"],
                registry=self.registry,
            )
            self.http_latency = Histogram(
                "gm_http_request_duration_seconds",
                "HTTP request duration (s)",
                ["method", "route"],
                buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
                registry=self.registry,
            )
            self.http_exceptions = Counter(
                "gm_http_exceptions_total",
                "Unhandled HTTP exceptions",
                ["route", "code"],
                registry=self.registry,
            )
            self.rate_limit_hits = Counter(
                "gm_rate_limit_hits_total",
                "Rate-limit rejections",
                ["scope"],
                registry=self.registry,
            )
            self.circuit_state = Gauge(
                "gm_circuit_state",
                "Circuit breaker state (0=closed,1=half,2=open)",
                ["name"],
                registry=self.registry,
            )
        else:
            self.registry = None  # type: ignore
            self.http_requests = Counter()  # type: ignore
            self.http_latency = Histogram()  # type: ignore
            self.http_exceptions = Counter()  # type: ignore
            self.rate_limit_hits = Counter()  # type: ignore
            self.circuit_state = Gauge()  # type: ignore

    def record_http(self, method: str, route: str, status: int, seconds: float) -> None:
        try:
            self.http_requests.labels(method=method, route=route, status=str(status)).inc()
            self.http_latency.labels(method=method, route=route).observe(seconds)
        except Exception as exc:  # noqa: BLE001
            log.debug("metrics_record_failed", err=str(exc))

    def render(self) -> tuple[bytes, str]:
        if _PROM and self.registry is not None:
            return generate_latest(self.registry), CONTENT_TYPE_LATEST
        return b"# prometheus_client not installed\n", CONTENT_TYPE_LATEST


metrics_service = MetricsService()
