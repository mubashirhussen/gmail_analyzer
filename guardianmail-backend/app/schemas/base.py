"""Shared Pydantic schemas — pagination, filtering, envelope responses."""
from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class PageParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(25, ge=1, le=200)

    @property
    def skip(self) -> int:
        return (self.page - 1) * self.page_size


class SortParams(BaseModel):
    sort_by: str | None = None
    sort_dir: int = Field(-1, ge=-1, le=1)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return (self.total + self.page_size - 1) // self.page_size if self.page_size else 0


class OKResponse(BaseModel):
    ok: bool = True
    message: str | None = None
