"""Sync-run audit record.

Every Gmail synchronisation run (initial, incremental, manual, scheduled)
writes exactly one SyncLog document so operations can trace throughput,
failures, and rate-limit backoffs without spelunking Celery logs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.models.base import Document

SyncKind = Literal["initial", "incremental", "manual", "scheduled", "resume"]
SyncStatus = Literal["running", "success", "partial", "failed", "cancelled"]


class SyncLog(Document):
    user_id: str
    connection_id: str
    kind: SyncKind
    status: SyncStatus = "running"

    # cursors
    started_history_id: str | None = None
    ended_history_id: str | None = None

    # counters
    messages_scanned: int = 0
    messages_ingested: int = 0
    messages_updated: int = 0
    messages_skipped: int = 0
    threads_touched: int = 0
    labels_synced: int = 0
    api_calls: int = 0
    retries: int = 0

    # timing
    started_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    finished_at: datetime | None = None
    duration_ms: int | None = None

    # error
    error_code: str | None = None
    error_message: str | None = None
