"""OCR API request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OCRUploadRequest(BaseModel):
    """base64-encoded upload — used when direct multipart isn't practical."""
    filename: str = Field(min_length=1, max_length=512)
    mime_type: str = Field(min_length=1, max_length=255)
    data_b64: str = Field(min_length=1)
    source: str = "upload"
    email_id: str | None = None
    forward_to_threat_intel: bool = True
    forward_to_ai: bool = False


class OCRAnalyzeRequest(BaseModel):
    """Analyse a previously-uploaded attachment by its report id."""
    report_id: str
    forward_to_threat_intel: bool = True
    forward_to_ai: bool = True


class OCRReportSummary(BaseModel):
    id: str
    user_id: str
    filename: str
    status: str
    ocr_confidence: float
    page_count: int
    processing_time_ms: int
    detected_url_count: int = 0
    detected_qr_count: int = 0
    detected_sensitive_count: int = 0
    risk_flag_count: int = 0
    created_at: datetime
    completed_at: datetime | None = None


class OCRReportDetail(BaseModel):
    id: str
    user_id: str
    status: str
    source: str
    extracted_text: str
    text_truncated: bool
    ocr_confidence: float
    processing_time_ms: int
    page_count: int
    engines_used: list[str] = Field(default_factory=list)
    patterns: dict[str, Any] = Field(default_factory=dict)
    qr_results: list[dict[str, Any]] = Field(default_factory=list)
    sensitive: dict[str, Any] = Field(default_factory=dict)
    security_indicators: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    attachment: dict[str, Any] = Field(default_factory=dict)
    threat_report_id: str | None = None
    ai_report_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class OCRJobAccepted(BaseModel):
    report_id: str
    status: str = "queued"
    async_task_id: str | None = None
