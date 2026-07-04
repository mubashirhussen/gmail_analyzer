import time
import uuid
import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        structlog.contextvars.bind_contextvars(request_id=rid, path=request.url.path)
        start = time.perf_counter()
        try:
            resp = await call_next(request)
            resp.headers["x-request-id"] = rid
            return resp
        finally:
            dur_ms = round((time.perf_counter() - start) * 1000, 2)
            structlog.get_logger().info("http", ms=dur_ms)
            structlog.contextvars.clear_contextvars()
