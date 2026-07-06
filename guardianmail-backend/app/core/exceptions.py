"""Domain exceptions + FastAPI handlers."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import structlog

log = structlog.get_logger()


class GuardianError(Exception):
    status_code = 400
    code = "guardian_error"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class AuthError(GuardianError):
    status_code = 401
    code = "auth_error"


class ForbiddenError(GuardianError):
    status_code = 403
    code = "forbidden"


class NotFoundError(GuardianError):
    status_code = 404
    code = "not_found"


class RateLimitError(GuardianError):
    status_code = 429
    code = "rate_limited"


class ThreatIntelError(GuardianError):
    status_code = 502
    code = "threat_intel_upstream"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(GuardianError)
    async def _handle(_: Request, exc: GuardianError):
        log.warning("guardian_error", code=exc.code, msg=exc.message)
        return JSONResponse(
            {"error": {"code": exc.code, "message": exc.message}},
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def _fallback(_: Request, exc: Exception):
        log.exception("unhandled", err=str(exc))
        return JSONResponse(
            {"error": {"code": "internal", "message": "internal server error"}},
            status_code=500,
        )
