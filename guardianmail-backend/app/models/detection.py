"""Phase 17 — Advanced detection persistence models.

Additive collections used exclusively by the detection engine. Existing
threat/AI/OCR models are untouched.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


Classification = Literal["safe", "low", "medium", "high", "critical", "unknown"]


class DetectionResult(Document):
    """One correlated verdict for an email/URL/threat."""

    user_id: str
    email_id: str | None = None
    threat_id: str | None = None
    subject: str | None = None
    sender: str | None = None

    classification: Classification = "unknown"
    risk_score: float = 0.0                 # 0..100
    confidence: float = 0.0                 # 0..1
    attack_complexity: str = "low"          # low/medium/high
    potential_impact: str = "low"           # low/medium/high/critical

    categories: list[str] = Field(default_factory=list)
    signals: list[dict[str, Any]] = Field(default_factory=list)
    fraud_findings: list[dict[str, Any]] = Field(default_factory=list)
    behavior: dict[str, Any] = Field(default_factory=dict)
    language: dict[str, Any] = Field(default_factory=dict)
    header: dict[str, Any] = Field(default_factory=dict)
    domain: dict[str, Any] = Field(default_factory=dict)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    ai_generated: dict[str, Any] = Field(default_factory=dict)

    recommendation: str = "review"
    recommendation_actions: list[str] = Field(default_factory=list)
    execution_ms: int = 0


class SenderBehaviorProfile(Document):
    """Rolling per-user, per-sender profile for behaviour analysis."""

    user_id: str
    sender: str                            # normalized (lowercased) email
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)
    total_messages: int = 0
    replied_messages: int = 0
    flagged_messages: int = 0
    trusted: bool = False
    domains: list[str] = Field(default_factory=list)
    avg_subject_len: float = 0.0
    last_verdict: str | None = None


class FraudIndicator(Document):
    """Persisted fraud/BEC signal linked to a detection result."""

    user_id: str
    detection_id: str
    email_id: str | None = None
    kind: str                              # 'wire_transfer', 'gift_card', ...
    severity: str = "medium"               # low/medium/high/critical
    value: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
