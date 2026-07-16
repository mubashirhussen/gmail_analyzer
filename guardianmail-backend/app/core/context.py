"""Request-scoped context (contextvars) shared by logging + middleware."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(slots=True)
class RequestCtx:
    request_id: str = ""
    user_id: str = ""
    device_id: str = ""
    ip: str = ""
    method: str = ""
    path: str = ""


_ctx: ContextVar[RequestCtx] = ContextVar("guardian_request_ctx", default=RequestCtx())


def get() -> RequestCtx:
    return _ctx.get()


def set(ctx: RequestCtx) -> None:  # noqa: A001
    _ctx.set(ctx)


def bind(**fields) -> RequestCtx:
    current = _ctx.get()
    updated = RequestCtx(**{**current.__dict__, **fields})
    _ctx.set(updated)
    return updated


def reset() -> None:
    _ctx.set(RequestCtx())
