"""Shared MongoDB document base."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.clock import now_utc
from app.core.ids import uuid_str


class Document(BaseModel):
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    id: str = Field(default_factory=uuid_str, alias="_id")
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)

    def to_mongo(self) -> dict[str, Any]:
        d = self.model_dump(by_alias=True)
        return d
