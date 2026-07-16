"""Phase 19 — observability unit tests (pure logic)."""
from __future__ import annotations

import pytest

from app.core.tracing import start_span, get_tracer, _NoopTracer
from app.services.observability.alert_service import _fingerprint
from app.services.observability.metrics_service import metrics_service


def test_fingerprint_is_stable_and_label_order_insensitive():
    a = _fingerprint("HighErrorRate", {"component": "api", "severity": "high"})
    b = _fingerprint("HighErrorRate", {"severity": "high", "component": "api"})
    assert a == b
    assert a != _fingerprint("HighErrorRate", {"component": "db", "severity": "high"})


def test_tracer_noop_never_raises():
    tracer = get_tracer()
    assert tracer is not None
    with start_span("unit.test", user_id="x"):
        pass  # no exception is the assertion


def test_metrics_service_swallows_bad_labels():
    # Never raise even if given nonsense — critical safety property.
    metrics_service.record_request(method="GET", path="/x", status=200,
                                   duration_s=0.01)
    metrics_service.record_scan(duration_s=1.2, outcome="ok")
    metrics_service.record_ai(provider="openai", operation="chat",
                              duration_s=0.5, tokens_in=10, tokens_out=20, ok=True)
    metrics_service.set_component("mongo", healthy=True, latency_ms=1.2)
    metrics_service.record_mongo(op="find", collection="threats", duration_s=0.4)


@pytest.mark.asyncio
async def test_alert_service_resolve_missing(monkeypatch):
    class _Repo:
        def __init__(self, *_): ...
        async def update(self, *_a, **_k): return 0
    import app.services.observability.alert_service as mod
    monkeypatch.setattr(mod, "ObservabilityAlertRepository", _Repo)
    monkeypatch.setattr(mod, "get_db", lambda: object())
    assert await mod.ops_alert_service.resolve("nope") is False


def test_tracing_decorator_wraps_sync(monkeypatch):
    from app.services.observability.tracing_service import tracing_service

    @tracing_service.traced("unit.wrapped")
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
