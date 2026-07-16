"""Tracing service — thin facade around OpenTelemetry.

Provides a ``span(name, **attrs)`` context manager and a decorator so
domain code stays free of OTel imports and works even when the SDK is
not installed (no-op tracer).
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Iterator

from app.core.tracing import get_tracer, start_span


class TracingService:
    @contextmanager
    def span(self, name: str, **attrs: Any) -> Iterator[Any]:
        with start_span(name, **attrs) as s:
            yield s

    def traced(self, name: str | None = None, **default_attrs: Any) -> Callable:
        def decorator(fn: Callable) -> Callable:
            span_name = name or f"{fn.__module__}.{fn.__qualname__}"

            if _is_coro(fn):
                @wraps(fn)
                async def _async(*a, **k):
                    with self.span(span_name, **default_attrs):
                        return await fn(*a, **k)
                return _async

            @wraps(fn)
            def _sync(*a, **k):
                with self.span(span_name, **default_attrs):
                    return fn(*a, **k)
            return _sync
        return decorator

    def tracer(self):
        return get_tracer()


def _is_coro(fn: Callable) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


tracing_service = TracingService()
