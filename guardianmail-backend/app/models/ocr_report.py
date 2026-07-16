"""OCR report document — output of the Document Intelligence pipeline.

Persisted after every successful (or failed) OCR run. Downstream consumers:

* Module 5 (Threat Intel) — reads `detected_urls` / `detected_domains` /
  `qr_results` to enrich its indicator graph.
* Module 6 (AI Engine) — reads `extracted_text` (bounded) and
  `security_indicators` to ground prompts.
* API layer — surfaces to the frontend without exposing raw sensitive data
  (the `sensitive_summary` masks values; original bytes never persist).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.core.clock import now_utc
from app.models.base import Document


OCRStatus = Literal["pending", "processing", "completed", "failed", "unsupported"]


class QRResult(BaseModel):
    payload: str
    type: str = "QRCODE"
    is_url: bool = False
    category: Literal[
        "url", "email", "phone", "upi", "payment", "wifi", "vcard", "text"
    ] = "text"


class SensitiveSummary(BaseModel):
    """Per-report tallies. Individual values are masked before storage."""
    counts: dict[str, int] = Field(default_factory=dict)
    samples: dict[str, list[str]] = Field(default_factory=dict)  # masked previews


class SecurityIndicators(BaseModel):
    suspicious_urls: list[str] = Field(default_factory=list)
    shortened_urls: list[str] = Field(default_factory=list)
    typosquat_candidates: list[str] = Field(default_factory=list)
    embedded_emails: list[str] = Field(default_factory=list)
    urgent_language: list[str] = Field(default_factory=list)
    credential_prompts: list[str] = Field(default_factory=list)
    payment_prompts: list[str] = Field(default_factory=list)
    invoice_signals: list[str] = Field(default_factory=list)
    brand_mentions: list[str] = Field(default_factory=list)


class DocumentMetadata(BaseModel):
    filename: str
    extension: str = ""
    size_bytes: int = 0
    mime_type: str = ""
    author: str | None = None
    creator: str | None = None
    producer: str | None = None
    software: str | None = None
    doc_created_at: datetime | None = None
    doc_modified_at: datetime | None = None
    page_count: int = 0
    embedded_links: list[str] = Field(default_factory=list)
    embedded_files: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class AttachmentAnalysis(BaseModel):
    filename: str
    extension: str = ""
    mime_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    double_extension: bool = False
    is_executable: bool = False
    is_archive: bool = False
    is_encrypted: bool = False
    contains_macros: bool = False
    embedded_objects: int = 0
    hyperlinks: list[str] = Field(default_factory=list)
    known_bad_hash: bool = False
    risk_flags: list[str] = Field(default_factory=list)


class ExtractedPatterns(BaseModel):
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    dates: list[str] = Field(default_factory=list)
    amounts: list[str] = Field(default_factory=list)
    account_numbers: list[str] = Field(default_factory=list)  # masked
    reference_ids: list[str] = Field(default_factory=list)
    invoice_numbers: list[str] = Field(default_factory=list)
    tracking_numbers: list[str] = Field(default_factory=list)


class OCRReport(Document):
    """One report per (user, upload). Idempotent on `sha256`."""

    user_id: str
    email_id: str | None = None
    source: Literal["upload", "gmail_attachment", "forward", "api"] = "upload"
    status: OCRStatus = "pending"

    # ---- content ----
    extracted_text: str = ""
    text_truncated: bool = False
    ocr_confidence: float = 0.0
    processing_time_ms: int = 0
    page_count: int = 0
    engines_used: list[str] = Field(default_factory=list)  # e.g. ["tesseract","pymupdf"]

    # ---- structured signals ----
    patterns: ExtractedPatterns = Field(default_factory=ExtractedPatterns)
    qr_results: list[QRResult] = Field(default_factory=list)
    sensitive: SensitiveSummary = Field(default_factory=SensitiveSummary)
    security_indicators: SecurityIndicators = Field(default_factory=SecurityIndicators)
    metadata: DocumentMetadata = Field(default_factory=lambda: DocumentMetadata(filename=""))
    attachment: AttachmentAnalysis = Field(default_factory=lambda: AttachmentAnalysis(filename=""))

    # ---- pipeline linkage ----
    threat_report_id: str | None = None
    ai_report_id: str | None = None
    forwarded_to_threat_at: datetime | None = None
    forwarded_to_ai_at: datetime | None = None

    # ---- errors ----
    error_code: str | None = None
    error_message: str | None = None
    retry_count: int = 0

    completed_at: datetime | None = None

    def mark_completed(self) -> None:
        self.status = "completed"
        self.completed_at = now_utc()
        self.touch()

    def mark_failed(self, code: str, message: str) -> None:
        self.status = "failed"
        self.error_code = code
        self.error_message = message[:1000]
        self.touch()
