"""Phase 16 — AI Security Copilot persistence models.

Additive collections used exclusively by the Copilot service. Existing AI /
Threat / Evidence models are untouched.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


Role = Literal["user", "assistant", "system"]


class CopilotConversation(Document):
    """A short-lived investigation session scoped to one scan/threat."""

    user_id: str
    scope: dict[str, Any] = Field(default_factory=dict)
    # e.g. {"threat_id": "...", "email_id": "...", "scan_id": "..."}
    title: str | None = None
    provider: str | None = None
    last_message_at: datetime = Field(default_factory=now_utc)
    message_count: int = 0
    archived: bool = False


class CopilotMessage(Document):
    conversation_id: str
    user_id: str
    role: Role
    content: str
    # Metadata captured for auditability / debugging.
    provider: str | None = None
    model: str | None = None
    latency_ms: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    validation: dict[str, Any] | None = None
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    structured: dict[str, Any] | None = None
