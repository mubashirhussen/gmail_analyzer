"""ASGI middleware stack (request id, timing, security headers, body limit)."""
from __future__ import annotations

import time

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core import context
from app.core.config import settings
from app.core.ids import request_id as gen_request_id

log = structlog.get_logger("http")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id, bind logging context, emit access log."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or gen_request_id()
        context.set(context.RequestCtx(
            request_id=rid,
            ip=request.client.host if request.client else "",
            method=request.method,
            path=request.url.path,
        ))
        structlog.contextvars.bind_contextvars(request_id=rid)
        start = time.perf_counter()
        status = 500
        try:
            resp: Response = await call_next(request)
            status = resp.status_code
            resp.headers["x-request-id"] = rid
            return resp
        finally:
            dur_ms = round((time.perf_counter() - start) * 1000, 2)
            log.info(
                "access",
                method=request.method,
                path=request.url.path,
                status=status,
                ms=dur_ms,
            )
            structlog.contextvars.clear_contextvars()
            context.reset()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if settings.is_prod:
            h.setdefault("Strict-Transport-Security",
                         "max-age=31536000; includeSubDomains; preload")
            h.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: https:; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self' https:; frame-ancestors 'none'",
            )
        return resp


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            from app.core.exceptions import ValidationError
            raise ValidationError(
                f"payload too large (>{self.max_bytes} bytes)",
                code="payload_too_large",
                status_code=413,
            )
        return await call_next(request)
