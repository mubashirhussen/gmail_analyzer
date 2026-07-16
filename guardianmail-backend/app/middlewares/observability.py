"""Module 11 — observability middleware.

Feeds the platform MetricsService and PerformanceService with per-request
data. Kept separate from `app.core.middleware.RequestContextMiddleware`
(which owns request-id + access log) so hardening can be enabled or
disabled independently.
"""
from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.services.platform.metrics_service import metrics_service
from app.services.platform.performance_service import performance_service


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path
    return request.url.path


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        status_code = 500
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            metrics_service.http_exceptions.labels(
                route=_route_template(request), code="unhandled"
            ).inc()
            raise
        finally:
            elapsed = time.perf_counter() - start
            performance_service.observe_ms(elapsed * 1000)
            metrics_service.record_http(
                request.method, _route_template(request), status_code, elapsed
            )
