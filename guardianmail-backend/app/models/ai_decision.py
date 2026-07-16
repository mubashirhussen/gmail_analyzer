"""Immutable AI decision history entry.

Every completed AI analysis appends a compact snapshot here. Unlike
`AIReport` (which may be re-analyzed and overwritten), this collection is
append-only and drives auditing, trend analysis, and drift detection.
"""
from __future__ import annotations

from typing import Literal

from app.models.base import Document

DecisionOutcome = Literal["accepted", "rejected", "degraded", "fallback"]


class AIDecisionHistory(Document):
    user_id: str
    ai_report_id: str
    threat_report_id: str
    email_id: str | None = None
    verdict: str = "unknown"
    risk_level: str = "none"
    confidence: float = 0.0
    prompt_hash: str = ""
    prompt_version: str = ""
    model_name: str = ""
    outcome: DecisionOutcome = "accepted"
    reasoning_count: int = 0
    evidence_count: int = 0
    duration_ms: int | None = None
