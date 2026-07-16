"""Shared MongoDB document base.

Every persisted collection extends `Document`. It supplies the invariants
every repository/service assumes:

* `_id` — string UUID; never Mongo ObjectId (avoids driver-specific leakage
  across the API/DTO boundary).
* `created_at` / `updated_at` — always UTC, sourced from `core.clock.now_utc`.
* `deleted_at` — soft-delete tombstone (`None` for live rows). Repositories
  filter it out by default; hard delete stays available for GDPR erasure.
* `version` — monotonically increasing revision for optimistic concurrency
  control in repositories that opt in.
"""
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
    deleted_at: datetime | None = None
    version: int = 0

    def to_mongo(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True)

    def touch(self) -> None:
        self.updated_at = now_utc()
        self.version += 1
