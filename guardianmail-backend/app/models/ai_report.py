"""AI Analysis Report document.

The `AIReport` is the canonical output of the Module 6 Explainable AI
Decision Engine. Each row is bound one-to-one with a `ThreatReport`
(Module 5) via `threat_report_id` and preserves *why* the model reached
its verdict, *what* evidence it consumed, and *what* the user should do.

Design invariants
-----------------
* AI never sees raw Gmail data — the engine hydrates its prompt strictly
  from the linked `ThreatReport`.
* Every stored report is fully self-contained (verdict + reasoning +
  recommendations + confidence). Downstream consumers never need to
  re-hydrate the prompt to render the UI.
* `prompt_hash`, `prompt_version`, and `model_version` are persisted for
  reproducibility, A/B experiments, and audit trails.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.base import Document

AIVerdict = Literal[
    "safe",
    "suspicious",
    "spam",
    "phishing",
    "credential_theft",
    "business_email_compromise",
    "malware",
    "invoice_fraud",
    "payment_scam",
    "identity_theft",
    "fake_login",
    "qr_phishing",
    "unknown",
]

RiskLevel = Literal["none", "low", "medium", "high", "critical"]
AIStatus = Literal["pending", "running", "completed", "failed", "degraded"]


class ConfidenceBreakdown(Document):
    """Multi-axis confidence for the AI decision (all 0..100)."""

    overall: float = 0.0
    evidence_strength: float = 0.0
    provider_agreement: float = 0.0
    model_confidence: float = 0.0
    data_completeness: float = 0.0
    reliability: float = 0.0


class Recommendation(Document):
    action: str
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    rationale: str = ""
    category: Literal["immediate", "long_term", "educational", "technical"] = "immediate"


class EvidenceRef(Document):
    """Pointer to a specific ThreatReport indicator the AI cited."""

    category: str
    detail: str
    severity: str = "info"
    weight: float = 0.0


class AIReport(Document):
    # ---------- provenance ------------------------------------------------
    user_id: str
    threat_report_id: str
    email_id: str | None = None
    channel: Literal["email", "url", "manual", "recheck"] = "email"
    triggered_by: Literal["auto", "user", "cron", "webhook"] = "auto"

    # ---------- lifecycle -------------------------------------------------
    status: AIStatus = "pending"
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    error_message: str | None = None

    # ---------- model + prompt fingerprint -------------------------------
    model_provider: str = "gemini"
    model_name: str = ""
    model_version: str = ""
    prompt_version: str = ""
    prompt_hash: str = ""
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

    # ---------- verdict --------------------------------------------------
    verdict: AIVerdict = "unknown"
    attack_type: str | None = None
    likely_objective: str | None = None
    risk_level: RiskLevel = "none"
    trust_score_adjustment: float = 0.0

    # ---------- explainability -------------------------------------------
    threat_summary: str = ""
    executive_summary: str = ""
    detailed_explanation: str = ""
    reasoning: list[str] = Field(default_factory=list)
    evidence_used: list[EvidenceRef] = Field(default_factory=list)
    possible_consequences: list[str] = Field(default_factory=list)
    user_impact: str = ""

    # ---------- confidence -----------------------------------------------
    confidence: ConfidenceBreakdown = Field(default_factory=ConfidenceBreakdown)

    # ---------- recommendations ------------------------------------------
    recommendations: list[Recommendation] = Field(default_factory=list)
    immediate_actions: list[str] = Field(default_factory=list)
    long_term_recommendations: list[str] = Field(default_factory=list)

    # ---------- education + technical ------------------------------------
    educational_tips: list[str] = Field(default_factory=list)
    technical_notes: list[str] = Field(default_factory=list)

    # ---------- validation footprint -------------------------------------
    validation_passed: bool = False
    validation_errors: list[str] = Field(default_factory=list)
    hallucination_score: float = 0.0  # 0 = grounded .. 1 = fabricated
