"""Phase 19 — OpenTelemetry bootstrap.

Import-safe: if the OTel SDK is not installed the module exposes no-op
helpers so the app continues to run. When installed, ``configure_tracing``
wires an OTLP exporter (endpoint from env), a resource tagged with the
service name, and returns the tracer for domain instrumentation.

Never crashes callers. Never touches business modules.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator


class _NoopSpan:
    def set_attribute(self, *_a, **_k): pass
    def set_status(self, *_a, **_k): pass
    def record_exception(self, *_a, **_k): pass
    def end(self): pass
    def __enter__(self): return self
    def __exit__(self, *_a): return False


class _NoopTracer:
    @contextmanager
    def start_as_current_span(self, name: str, **_k) -> Iterator[_NoopSpan]:
        yield _NoopSpan()


_TRACER: Any = _NoopTracer()
_CONFIGURED = False


def configure_tracing(service_name: str = "guardianmail-api") -> None:
    """Wire the OTel SDK if present. Safe to call multiple times."""
    global _TRACER, _CONFIGURED
    if _CONFIGURED:
        return
    try:  # pragma: no cover - optional dep
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        endpoint = os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://otel-collector:4318/v1/traces",
        )
        resource = Resource.create({
            "service.name": service_name,
            "service.version": os.environ.get("APP_VERSION", "unknown"),
            "deployment.environment": os.environ.get("APP_ENV", "prod"),
        })
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        _TRACER = trace.get_tracer(service_name)
    except Exception:
        _TRACER = _NoopTracer()
    _CONFIGURED = True


def get_tracer() -> Any:
    if not _CONFIGURED:
        configure_tracing()
    return _TRACER


@contextmanager
def start_span(name: str, **attrs: Any) -> Iterator[Any]:
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as span:
        for k, v in attrs.items():
            try:
                span.set_attribute(k, v)
            except Exception:
                pass
        yield span
