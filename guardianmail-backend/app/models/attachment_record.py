"""Persistent attachment record — deduplicated by SHA-256.

Represents *file identity* rather than the raw bytes; we never persist the
attachment payload itself. Downstream repositories join `AttachmentRecord`
by `sha256` to cluster reuse of the same file across users and emails.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


AttachmentSource = Literal["upload", "gmail", "forward", "api"]


class AttachmentRecord(Document):
    sha256: str
    filename: str
    extension: str = ""
    mime_type: str = ""
    size_bytes: int = 0
    source: AttachmentSource = "upload"

    user_id: str
    email_id: str | None = None
    ocr_report_id: str | None = None

    # observed characteristics (mirrored from AttachmentAnalysis for search)
    double_extension: bool = False
    is_executable: bool = False
    is_archive: bool = False
    is_encrypted: bool = False
    contains_macros: bool = False
    known_bad_hash: bool = False
    risk_flags: list[str] = Field(default_factory=list)

    first_seen_at: datetime = Field(default_factory=now_utc)
    last_seen_at: datetime = Field(default_factory=now_utc)
    seen_count: int = 1
