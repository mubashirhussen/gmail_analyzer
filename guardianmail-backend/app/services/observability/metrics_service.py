"""Metrics service — thin, safe facade over the Prometheus registry.

All record_* methods swallow errors so instrumentation NEVER crashes a
caller. Business modules import this rather than the raw metrics module
so we can evolve the underlying registry without touching callers.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from app.core.logging import get_logger
from app.core.observability_metrics import (
    AI_FAILURES,
    AI_LATENCY,
    AI_TOKENS,
    AUTH_SUCCESS,
    COMPONENT_LATENCY,
    COMPONENT_UP,
    CONCURRENT_REQUESTS,
    GMAIL_SYNC_TOTAL,
    INCIDENTS_TOTAL,
    LOGIN_FAILURES,
    MONGO_OPS,
    MONGO_SLOW_QUERIES,
    OCR_DURATION,
    OCR_ITEMS,
    REDIS_HITS,
    REDIS_MISSES,
    REQUEST_DURATION,
    REQUESTS_TOTAL,
    SCAN_DURATION,
    TI_CACHE_HITS,
    TI_CACHE_MISSES,
    TI_PROVIDER_FAILURES,
    TI_PROVIDER_LATENCY,
)

_log = get_logger(__name__)


def _safe(fn):
    def _wrap(*a, **k):
        try:
            fn(*a, **k)
        except Exception as exc:  # pragma: no cover
            _log.debug("metrics_noop", err=str(exc))
    return _wrap


class MetricsService:
    # ---- request ---------------------------------------------------------
    @_safe
    def record_request(self, *, method: str, path: str, status: int, duration_s: float):
        REQUESTS_TOTAL.labels(method=method, path=path, status=str(status)).inc()
        REQUEST_DURATION.labels(method=method, path=path).observe(duration_s)

    def inc_in_flight(self): CONCURRENT_REQUESTS.inc()
    def dec_in_flight(self): CONCURRENT_REQUESTS.dec()

    # ---- auth ------------------------------------------------------------
    @_safe
    def record_login_failure(self, reason: str):
        LOGIN_FAILURES.labels(reason=reason[:40]).inc()

    @_safe
    def record_auth_success(self, kind: str = "password"):
        AUTH_SUCCESS.labels(kind=kind).inc()

    # ---- scanning --------------------------------------------------------
    @_safe
    def record_scan(self, *, duration_s: float, outcome: str = "ok"):
        SCAN_DURATION.labels(outcome=outcome).observe(duration_s)

    @_safe
    def record_incident(self, *, severity: str, source: str = "detection"):
        INCIDENTS_TOTAL.labels(severity=severity, source=source).inc()

    @_safe
    def record_gmail_sync(self, outcome: str = "ok"):
        GMAIL_SYNC_TOTAL.labels(outcome=outcome).inc()

    # ---- TI --------------------------------------------------------------
    @_safe
    def record_ti(self, *, provider: str, duration_s: float, ok: bool = True,
                  kind: str = "lookup"):
        TI_PROVIDER_LATENCY.labels(provider=provider).observe(duration_s)
        if not ok:
            TI_PROVIDER_FAILURES.labels(provider=provider, kind=kind).inc()

    @_safe
    def record_ti_cache(self, *, provider: str, hit: bool):
        (TI_CACHE_HITS if hit else TI_CACHE_MISSES).labels(provider=provider).inc()

    # ---- AI --------------------------------------------------------------
    @_safe
    def record_ai(self, *, provider: str, operation: str, duration_s: float,
                  tokens_in: int = 0, tokens_out: int = 0, ok: bool = True):
        AI_LATENCY.labels(provider=provider, operation=operation).observe(duration_s)
        if tokens_in:
            AI_TOKENS.labels(provider=provider, kind="input").inc(tokens_in)
        if tokens_out:
            AI_TOKENS.labels(provider=provider, kind="output").inc(tokens_out)
        if not ok:
            AI_FAILURES.labels(provider=provider, kind=operation).inc()

    # ---- OCR -------------------------------------------------------------
    @_safe
    def record_ocr(self, *, duration_s: float, outcome: str = "ok",
                   kind: str = "image", count: int = 1):
        OCR_DURATION.labels(outcome=outcome).observe(duration_s)
        OCR_ITEMS.labels(kind=kind).inc(count)

    # ---- infra -----------------------------------------------------------
    @_safe
    def set_component(self, component: str, *, healthy: bool, latency_ms: float | None = None):
        COMPONENT_UP.labels(component=component).set(1.0 if healthy else 0.0)
        if latency_ms is not None:
            COMPONENT_LATENCY.labels(component=component).set(float(latency_ms))

    @_safe
    def record_mongo(self, *, op: str, collection: str, duration_s: float,
                     slow_threshold_s: float = 0.25):
        MONGO_OPS.labels(op=op, collection=collection).inc()
        if duration_s >= slow_threshold_s:
            MONGO_SLOW_QUERIES.labels(collection=collection).inc()

    @_safe
    def record_redis(self, *, prefix: str, hit: bool):
        (REDIS_HITS if hit else REDIS_MISSES).labels(prefix=prefix).inc()

    # ---- helpers ---------------------------------------------------------
    @contextmanager
    def time(self, recorder, /, **labels) -> Iterator[None]:
        """Generic timing helper: ``with metrics.time(record_scan, outcome='ok'):``."""
        t0 = time.perf_counter()
        try:
            yield
        finally:
            try:
                recorder(duration_s=time.perf_counter() - t0, **labels)
            except Exception:
                pass


metrics_service = MetricsService()
