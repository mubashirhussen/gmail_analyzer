"""Phase 16 — Copilot request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CopilotScope(BaseModel):
    """Which GuardianMail artifact this investigation is scoped to.

    At least one of `threat_id` / `email_id` / `scan_id` must be provided;
    the Copilot refuses to answer without a verifiable evidence anchor.
    """

    threat_id: str | None = None
    email_id: str | None = None
    scan_id: str | None = None
    url: str | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = None
    scope: CopilotScope
    provider: str | None = None  # override; validated against registry


class ExplainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: CopilotScope
    aspect: Literal[
        "overall",
        "sender",
        "url",
        "attachment",
        "qr",
        "headers",
        "score",
        "recommendation",
    ] = "overall"
    provider: str | None = None


class SummarizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: CopilotScope
    style: Literal["executive", "technical", "user"] = "user"
    provider: str | None = None


class EvidenceRef(BaseModel):
    source: str                 # "threat_report", "email_headers", "ocr", ...
    ref_id: str | None = None
    field: str | None = None
    value: Any | None = None


class CopilotResponse(BaseModel):
    conversation_id: str
    message_id: str
    summary: str
    evidence: list[EvidenceRef]
    threat_indicators: list[str]
    ai_reasoning: str
    confidence: float
    recommended_action: str
    educational_tip: str
    related_concepts: list[str]
    provider: str
    model: str | None = None
    latency_ms: int
    validation: dict[str, Any]


class ConversationOut(BaseModel):
    id: str = Field(alias="_id")
    user_id: str
    scope: dict[str, Any]
    title: str | None
    provider: str | None
    last_message_at: datetime
    message_count: int

    model_config = ConfigDict(populate_by_name=True)


class MessageOut(BaseModel):
    id: str = Field(alias="_id")
    conversation_id: str
    role: str
    content: str
    provider: str | None = None
    latency_ms: int | None = None
    created_at: datetime
    structured: dict[str, Any] | None = None

    model_config = ConfigDict(populate_by_name=True)
