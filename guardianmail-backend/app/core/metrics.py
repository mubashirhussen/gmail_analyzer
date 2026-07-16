"""Prometheus metrics for the background-processing platform.

`prometheus_client` is optional at import time — if it isn't installed
we return a no-op registry so the app still boots on stripped-down images
(e.g. the FastAPI-only container). Workers ship with the dependency.
"""
from __future__ import annotations

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram,
        generate_latest,
    )
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

    CONTENT_TYPE_LATEST = "text/plain"

    class _NoOp:  # noqa: D401 - simple stub
        def __init__(self, *a, **k): pass
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass

    Counter = Gauge = Histogram = _NoOp  # type: ignore[assignment]
    CollectorRegistry = object  # type: ignore[assignment]

    def generate_latest(_registry=None) -> bytes:  # type: ignore[misc]
        return b"# prometheus_client not installed\n"


REGISTRY = CollectorRegistry() if _HAS_PROM else None

# ---- task metrics -----------------------------------------------------------
TASK_STARTED = Counter(
    "guardianmail_task_started_total",
    "Tasks that started executing.",
    ["task", "queue"],
    registry=REGISTRY,
) if _HAS_PROM else Counter()

TASK_SUCCEEDED = Counter(
    "guardianmail_task_succeeded_total",
    "Tasks that completed successfully.",
    ["task", "queue"],
    registry=REGISTRY,
) if _HAS_PROM else Counter()

TASK_FAILED = Counter(
    "guardianmail_task_failed_total",
    "Tasks that raised an unhandled exception.",
    ["task", "queue", "exception"],
    registry=REGISTRY,
) if _HAS_PROM else Counter()

TASK_RETRIED = Counter(
    "guardianmail_task_retried_total",
    "Tasks that scheduled an automatic retry.",
    ["task", "queue"],
    registry=REGISTRY,
) if _HAS_PROM else Counter()

TASK_DURATION = Histogram(
    "guardianmail_task_duration_seconds",
    "Wall-clock task duration.",
    ["task", "queue"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600),
    registry=REGISTRY,
) if _HAS_PROM else Histogram()

QUEUE_DEPTH = Gauge(
    "guardianmail_queue_depth",
    "Live queue depth polled by the monitoring service.",
    ["queue"],
    registry=REGISTRY,
) if _HAS_PROM else Gauge()

DEAD_LETTER_SIZE = Gauge(
    "guardianmail_dead_letter_size",
    "Entries in the dead-letter stream.",
    registry=REGISTRY,
) if _HAS_PROM else Gauge()


def render() -> tuple[bytes, str]:
    if not _HAS_PROM:
        return generate_latest(), CONTENT_TYPE_LATEST
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
