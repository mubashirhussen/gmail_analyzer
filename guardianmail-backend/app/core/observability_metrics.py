"""Phase 19 — Observability metrics registry.

Additive on top of ``app.core.metrics``. Nothing here mutates the existing
task/queue metrics — this module ONLY declares the new
``guardian_*`` series required by the enterprise observability layer.

The metrics module is designed to be import-safe even when
``prometheus_client`` is missing: we re-use the same no-op fallbacks the
existing task metrics use, so workers/API containers without the library
still boot.
"""
from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

    class _NoOp:
        def __init__(self, *a, **k): pass
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass

    Counter = Gauge = Histogram = _NoOp  # type: ignore[assignment]

from app.core.metrics import REGISTRY  # share the app registry


def _c(name: str, doc: str, labels: list[str] | None = None):
    if _HAS_PROM:
        return Counter(name, doc, labels or [], registry=REGISTRY)
    return Counter()


def _g(name: str, doc: str, labels: list[str] | None = None):
    if _HAS_PROM:
        return Gauge(name, doc, labels or [], registry=REGISTRY)
    return Gauge()


def _h(name: str, doc: str, labels: list[str] | None = None, buckets=None):
    if _HAS_PROM:
        return Histogram(
            name, doc, labels or [], registry=REGISTRY,
            buckets=buckets or (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
        )
    return Histogram()


# ---- application ---------------------------------------------------------
REQUESTS_TOTAL = _c(
    "guardian_requests_total",
    "HTTP requests handled by the FastAPI app.",
    ["method", "path", "status"],
)
REQUEST_DURATION = _h(
    "guardian_request_duration_seconds",
    "HTTP request latency.",
    ["method", "path"],
)
CONCURRENT_REQUESTS = _g(
    "guardian_concurrent_requests",
    "In-flight HTTP requests.",
)
LOGIN_FAILURES = _c(
    "guardian_login_failures_total",
    "Failed authentication attempts.",
    ["reason"],
)
AUTH_SUCCESS = _c(
    "guardian_auth_success_total",
    "Successful authentications.",
    ["kind"],
)

# ---- scanning / threats --------------------------------------------------
SCAN_DURATION = _h(
    "guardian_scan_duration_seconds",
    "End-to-end email scan duration.",
    ["outcome"],
)
INCIDENTS_TOTAL = _c(
    "guardian_incidents_total",
    "Security incidents created.",
    ["severity", "source"],
)
GMAIL_SYNC_TOTAL = _c(
    "guardian_gmail_sync_total",
    "Gmail sync executions.",
    ["outcome"],
)

# ---- threat intelligence -------------------------------------------------
TI_PROVIDER_LATENCY = _h(
    "guardian_ti_provider_latency_seconds",
    "Threat intel provider latency.",
    ["provider"],
)
TI_PROVIDER_FAILURES = _c(
    "guardian_provider_failures_total",
    "Failed provider calls.",
    ["provider", "kind"],
)
TI_CACHE_HITS = _c(
    "guardian_ti_cache_hits_total",
    "Threat intel cache hits.",
    ["provider"],
)
TI_CACHE_MISSES = _c(
    "guardian_ti_cache_misses_total",
    "Threat intel cache misses.",
    ["provider"],
)

# ---- AI ------------------------------------------------------------------
AI_LATENCY = _h(
    "guardian_ai_latency_seconds",
    "AI provider round-trip latency.",
    ["provider", "operation"],
)
AI_TOKENS = _c(
    "guardian_ai_tokens_total",
    "AI tokens consumed.",
    ["provider", "kind"],
)
AI_FAILURES = _c(
    "guardian_ai_failures_total",
    "AI provider errors.",
    ["provider", "kind"],
)

# ---- OCR -----------------------------------------------------------------
OCR_DURATION = _h(
    "guardian_ocr_duration_seconds",
    "OCR execution duration.",
    ["outcome"],
)
OCR_ITEMS = _c(
    "guardian_ocr_items_total",
    "OCR items processed.",
    ["kind"],
)

# ---- queues / infra ------------------------------------------------------
QUEUE_DEPTH = _g(
    "guardian_queue_depth",
    "Celery queue depth (observability view).",
    ["queue"],
)
COMPONENT_UP = _g(
    "guardian_component_up",
    "1 if a component is healthy, 0 if degraded/down.",
    ["component"],
)
COMPONENT_LATENCY = _g(
    "guardian_component_latency_ms",
    "Last observed probe latency in ms.",
    ["component"],
)

# ---- DB / redis ----------------------------------------------------------
MONGO_OPS = _c(
    "guardian_mongo_ops_total",
    "Mongo operations by kind.",
    ["op", "collection"],
)
MONGO_SLOW_QUERIES = _c(
    "guardian_mongo_slow_queries_total",
    "Mongo queries slower than threshold.",
    ["collection"],
)
REDIS_HITS = _c("guardian_redis_hits_total", "Redis cache hits.", ["prefix"])
REDIS_MISSES = _c("guardian_redis_misses_total", "Redis cache misses.", ["prefix"])


__all__ = [
    "REQUESTS_TOTAL", "REQUEST_DURATION", "CONCURRENT_REQUESTS",
    "LOGIN_FAILURES", "AUTH_SUCCESS",
    "SCAN_DURATION", "INCIDENTS_TOTAL", "GMAIL_SYNC_TOTAL",
    "TI_PROVIDER_LATENCY", "TI_PROVIDER_FAILURES",
    "TI_CACHE_HITS", "TI_CACHE_MISSES",
    "AI_LATENCY", "AI_TOKENS", "AI_FAILURES",
    "OCR_DURATION", "OCR_ITEMS",
    "QUEUE_DEPTH", "COMPONENT_UP", "COMPONENT_LATENCY",
    "MONGO_OPS", "MONGO_SLOW_QUERIES", "REDIS_HITS", "REDIS_MISSES",
]
