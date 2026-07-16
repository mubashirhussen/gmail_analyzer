"""Report record — persisted metadata for generated report artifacts.

The bytes of a report may live in object storage; this document stores
lifecycle state, download URL, size, checksum, and audit fields so the
frontend can list, poll, and download historically generated reports.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document

ReportKind = Literal[
    "daily", "weekly", "monthly",
    "security", "threat", "executive",
    "email_activity", "analytics_snapshot",
]
ReportFormat = Literal["pdf", "csv", "xlsx", "json", "docx"]
ReportStatus = Literal["pending", "running", "ready", "failed", "expired"]


class ReportRecord(Document):
    user_id: str
    kind: ReportKind
    fmt: ReportFormat
    status: ReportStatus = "pending"

    period_start: datetime | None = None
    period_end: datetime | None = None
    generated_at: datetime | None = None
    expires_at: datetime | None = None

    size_bytes: int | None = None
    mime: str | None = None
    storage_url: str | None = None
    checksum_sha256: str | None = None
    download_token: str | None = None
    download_count: int = 0
    last_downloaded_at: datetime | None = None

    error: str | None = None
    summary: dict = Field(default_factory=dict)
    filters: dict = Field(default_factory=dict)

    requested_by: str | None = None
    requested_at: datetime = Field(default_factory=now_utc)
