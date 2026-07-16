"""Phase 17 — Detection request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_id: str | None = None
    threat_id: str | None = None
    # Optional inline payload for on-demand analysis (subject + body + headers).
    subject: str | None = Field(default=None, max_length=1000)
    sender: str | None = Field(default=None, max_length=320)
    body: str | None = Field(default=None, max_length=200_000)
    headers: dict[str, Any] | None = None
    urls: list[str] | None = None
    attachments: list[dict[str, Any]] | None = None


class DetectionOut(BaseModel):
    id: str = Field(alias="_id")
    user_id: str
    email_id: str | None = None
    threat_id: str | None = None
    classification: str
    risk_score: float
    confidence: float
    attack_complexity: str
    potential_impact: str
    categories: list[str]
    signals: list[dict[str, Any]]
    recommendation: str
    recommendation_actions: list[str]
    execution_ms: int
    created_at: datetime

    model_config = ConfigDict(populate_by_name=True)
