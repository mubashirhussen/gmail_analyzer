"""Unified success/pagination response envelope (Module 11).

Business handlers may keep returning bare models; this envelope is
opt-in for handlers that want the standardized shape:

    {"data": ..., "meta": {"request_id": ..., "pagination": ...}}
"""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

from app.core import context

T = TypeVar("T")


class Pagination(BaseModel):
    page: int = Field(ge=1, default=1)
    page_size: int = Field(ge=1, le=500, default=50)
    total: int = Field(ge=0, default=0)
    has_more: bool = False


class Meta(BaseModel):
    request_id: str | None = None
    pagination: Pagination | None = None
    extra: dict[str, Any] | None = None


class Envelope(BaseModel, Generic[T]):
    data: T
    meta: Meta


def envelope(data: Any, *, pagination: Pagination | None = None,
             extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "data": data,
        "meta": Meta(
            request_id=context.get().request_id or None,
            pagination=pagination,
            extra=extra,
        ).model_dump(exclude_none=True),
    }
