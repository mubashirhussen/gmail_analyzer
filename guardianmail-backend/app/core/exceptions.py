"""Domain exception hierarchy + FastAPI handlers.

All application errors inherit from `DomainError`. Handlers translate them
(and framework/validation errors) into a single `ErrorResponse` shape so
API clients only need to parse one envelope.
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core import context
from app.core.errors import ErrorEnvelope, ErrorResponse

log = structlog.get_logger(__name__)


class DomainError(Exception):
    status_code: int = 400
    code: str = "domain_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or None
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class ValidationError(DomainError):
    status_code = 422
    code = "validation_error"


class AuthError(DomainError):
    status_code = 401
    code = "unauthenticated"


class PermissionError(DomainError):  # noqa: A001
    status_code = 403
    code = "forbidden"


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"


class ConflictError(DomainError):
    status_code = 409
    code = "conflict"


class RateLimitError(DomainError):
    status_code = 429
    code = "rate_limited"


class ExternalServiceError(DomainError):
    status_code = 502
    code = "external_service_error"


class UnavailableError(DomainError):
    status_code = 503
    code = "unavailable"


# ---- legacy aliases (kept for existing business modules) -----------------
GuardianError = DomainError
ForbiddenError = PermissionError
ThreatIntelError = ExternalServiceError


def _envelope(code: str, message: str, *, details: dict | None = None) -> dict:
    payload = ErrorResponse(
        error=ErrorEnvelope(
            code=code,
            message=message,
            details=details,
            request_id=context.get().request_id or None,
        )
    )
    return payload.model_dump(exclude_none=True)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain(_: Request, exc: DomainError) -> JSONResponse:
        log.warning("domain_error", code=exc.code, msg=exc.message, details=exc.details)
        return JSONResponse(
            _envelope(exc.code, exc.message, details=exc.details),
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            _envelope("validation_error", "request validation failed",
                      details={"errors": exc.errors()}),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            _envelope(f"http_{exc.status_code}", str(exc.detail or "http error")),
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def _fallback(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_exception", err=str(exc))
        return JSONResponse(
            _envelope("internal", "internal server error"),
            status_code=500,
        )
