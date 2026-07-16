"""Task platform API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DispatchRequest(BaseModel):
    task_name: str = Field(min_length=1, max_length=200)
    args: list[Any] = Field(default_factory=list, max_length=32)
    kwargs: dict[str, Any] = Field(default_factory=dict)
    queue: str | None = None
    priority: int = Field(5, ge=1, le=9)
    dedup_key: str | None = Field(None, max_length=256)
    max_retries: int = Field(3, ge=0, le=10)
    countdown: int | None = Field(None, ge=0, le=24 * 3600)


class DispatchResponse(BaseModel):
    job_id: str
    task_id: str | None
    queue: str
    priority: int
    status: str


class JobView(BaseModel):
    id: str
    job_type: str
    status: str
    queue: str | None = None
    user_id: str | None = None
    task_id: str | None = None
    retry_count: int = 0
    max_retries: int = 3
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None


class PlatformHealth(BaseModel):
    redis: bool
    broker: bool
    dead_letter_size: int


class QueueDepthResponse(BaseModel):
    depths: dict[str, int]


class WorkersResponse(BaseModel):
    workers: dict[str, Any]


class DeadLetterEntry(BaseModel):
    id: str
    task: str
    task_id: str = ""
    queue: str = ""
    error: str = ""
    retry_count: str = "0"
    args: str = "[]"
    kwargs: str = "{}"
