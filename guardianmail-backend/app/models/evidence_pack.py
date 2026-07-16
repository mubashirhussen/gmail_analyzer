"""Evidence pack document — signed bundle of forensic artefacts.

An evidence pack is a signed manifest referencing the artefacts (headers,
indicators, URLs, screenshots) that back a threat report. Actual files
live in object storage; only the manifest and integrity metadata are
stored in Mongo.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.models.base import Document

PackStatus = Literal["generating", "ready", "downloaded", "expired", "failed"]


class EvidenceFile(Document):
    """Sub-document — one file inside a pack."""

    name: str
    mime: str
    size: int
    sha256: str
    storage_key: str


class EvidencePack(Document):
    user_id: str
    threat_report_id: str
    email_id: str | None = None

    status: PackStatus = "generating"
    files: list[EvidenceFile] = Field(default_factory=list)
    manifest_sha256: str | None = None
    signature: str | None = None  # HMAC over manifest

    generated_at: datetime | None = None
    expires_at: datetime | None = None
    downloaded_at: datetime | None = None
    download_count: int = 0
    failure_reason: str | None = None
