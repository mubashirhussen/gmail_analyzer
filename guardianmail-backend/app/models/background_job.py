"""Background job document — persisted lifecycle record for Celery tasks.

Celery owns execution; this collection owns *observability*: what was
requested, by whom, when it ran, how it ended. Services enqueueing a task
also write a `BackgroundJob` so users can see status in the UI.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.models.base import Document

JobStatus = Literal["pending", "queued", "running", "success", "failed", "cancelled"]


class BackgroundJob(Document):
    job_type: str  # e.g. "gmail.sync", "threat.rescan", "evidence.generate"
    user_id: str | None = None
    task_id: str | None = None  # Celery task id
    queue: str | None = None

    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None

    status: JobStatus = "pending"
    retry_count: int = 0
    max_retries: int = 3

    scheduled_for: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
