"""Threat report document.

A ThreatReport is the canonical output of the Threat Intelligence Engine
for a single email. It is intentionally *self-contained*: every field the
frontend, downstream AI reasoner (Module 6), analytics module, or
complaint pipeline needs is present without further joins.

Design notes
------------
* One report per (email_id, scan_generation). Re-scans create a new
  document — history is preserved for audit.
* IOC-level detail lives in `threat_indicators`; this document holds
  only summaries + rollups, so a single query fetches "what happened".
* Provider raw responses live in `provider_results` (append-only).
* All scores are floats in [0, 100] to keep the arithmetic uniform.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.base import Document

Verdict = Literal[
    "safe",
    "low_risk",
    "medium_risk",
    "high_risk",
    "critical",
    "unknown",
]

ThreatCategory = Literal[
    "safe",
    "phishing",
    "business_email_compromise",
    "credential_theft",
    "malware",
    "spam",
    "scam",
    "impersonation",
    "unknown",
]

Severity = Literal["info", "low", "medium", "high", "critical"]
ScanStatus = Literal["pending", "running", "partial", "completed", "failed"]


class ProviderStatus(Document):
    """Per-provider status snapshot embedded in the report."""

    provider: str
    status: Literal["ok", "skipped", "error", "timeout", "rate_limited", "unavailable"]
    latency_ms: int | None = None
    error_code: str | None = None
    error_message: str | None = None


class ScoreBundle(Document):
    """Composite scoring vector.

    * threat_score  — 0 safe .. 100 fully malicious
    * trust_score   — inverse-ish: 100 fully trusted
    * security_score — how well the sender's controls (SPF/DKIM/DMARC/TLS) hold up
    * confidence    — 0..1 confidence in the verdict given provider coverage
    """

    threat_score: float = 0.0
    trust_score: float = 100.0
    security_score: float = 100.0
    confidence: float = 0.0


class IndicatorRollup(Document):
    """Summary counts extracted from the linked ThreatIndicator rows."""

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_kind: dict[str, int] = Field(default_factory=dict)
    top: list[dict] = Field(default_factory=list)  # small excerpt for UI


class ThreatReport(Document):
    # ---------- provenance ------------------------------------------------
    user_id: str
    email_id: str | None = None  # optional — ad-hoc scans have no email
    scan_generation: int = 1
    channel: Literal["email", "url", "manual", "recheck"] = "email"
    triggered_by: Literal["auto_sync", "user_action", "cron", "webhook"] = "auto_sync"

    # ---------- verdict / classification ---------------------------------
    verdict: Verdict = "unknown"
    threat_category: ThreatCategory = "unknown"
    severity: Severity = "info"
    scores: ScoreBundle = Field(default_factory=ScoreBundle)
    risk_score: float = 0.0  # kept top-level for cheap indexed queries

    # ---------- provider coverage ----------------------------------------
    scan_status: ScanStatus = "pending"
    providers: list[ProviderStatus] = Field(default_factory=list)
    providers_ok: int = 0
    providers_total: int = 0

    # ---------- explainability -------------------------------------------
    summary: str = ""
    why: list[str] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    recommended_action: Literal[
        "allow", "monitor", "warn_user", "quarantine", "block", "report"
    ] = "monitor"

    # ---------- rollups --------------------------------------------------
    indicators: IndicatorRollup = Field(default_factory=IndicatorRollup)
    urls_analyzed: int = 0
    domains_analyzed: int = 0
    attachments_analyzed: int = 0

    # ---------- lifecycle ------------------------------------------------
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int | None = None
    review_status: Literal["unreviewed", "confirmed", "false_positive", "dismissed"] = "unreviewed"


# Backwards compatibility shim for early Module 3 callers that still
# imported `ThreatDoc`. New code should use `ThreatReport`.
ThreatDoc = ThreatReport
