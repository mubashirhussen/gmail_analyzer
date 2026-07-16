"""Email metadata document.

Metadata-first. The full body is only kept for messages explicitly
forwarded for scanning (``full_body_retained=True``); otherwise we keep a
snippet plus normalised headers, URLs, attachment metadata, and Gmail
identifiers required by downstream threat analysis.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.base import Document


class AttachmentMeta(BaseModel):
    filename: str | None = None
    extension: str | None = None
    mime: str | None = None
    size: int = 0
    sha256: str | None = None
    attachment_id: str | None = None
    stored: bool = False
    scan_status: Literal["pending", "clean", "suspicious", "malicious", "error"] = "pending"


class UrlRef(BaseModel):
    raw: str
    normalized: str
    scheme: str = ""
    domain: str = ""
    subdomain: str | None = None
    path: str | None = None
    query: str | None = None
    source: Literal["text", "html", "button", "image", "qr"] = "text"


class ParsedHeaders(BaseModel):
    """Normalised, security-relevant slice of an RFC-5322 header set."""

    message_id: str | None = None
    return_path: str | None = None
    reply_to: str | None = None
    received: list[str] = Field(default_factory=list)
    authentication_results: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    x_originating_ip: str | None = None
    user_agent: str | None = None
    mailer: str | None = None
    content_type: str | None = None
    list_unsubscribe: str | None = None


class EmailDoc(Document):
    user_id: str
    connection_id: str | None = None

    # Gmail identifiers
    gmail_id: str | None = None
    thread_id: str | None = None
    history_id: str | None = None

    # envelope
    sender: str = ""
    sender_name: str | None = None
    sender_email: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    recipients: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)

    subject: str = ""
    snippet: str = ""

    # optional body — only kept when the user explicitly submitted the email
    # for a forwarded/deep scan.
    body_text: str = ""
    body_html: str | None = None
    full_body_retained: bool = False

    # gmail metadata
    labels: list[str] = Field(default_factory=list)
    label_names: list[str] = Field(default_factory=list)
    is_unread: bool = False
    is_starred: bool = False
    is_important: bool = False
    categories: list[str] = Field(default_factory=list)
    mime_type: str | None = None
    size_estimate: int = 0

    # security artefacts
    headers: ParsedHeaders = Field(default_factory=ParsedHeaders)
    urls: list[UrlRef] = Field(default_factory=list)
    has_attachments: bool = False
    attachments: list[AttachmentMeta] = Field(default_factory=list)

    received_at: datetime
    ingested_at: datetime | None = None

    # analysis lifecycle
    analysis_status: Literal["pending", "running", "done", "error", "skipped"] = "pending"
    threat_id: str | None = None
