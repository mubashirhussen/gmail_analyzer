"""Threat Intelligence Engine — request / response DTOs.

These are the shapes exposed on `/api/v1/threats/*`. They deliberately
omit engine internals (raw provider payloads live in `provider_results`
and are only surfaced through the debug endpoint).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# -------------------------------------------------------------------- shared
class Indicator(BaseModel):
    category: str
    severity: str  # info|low|medium|high|critical
    detail: str
    evidence: dict[str, Any] | None = None


class ThreatVerdict(BaseModel):
    verdict: str
    risk_score: int
    confidence: int
    attack_category: str | None = None
    summary: str
    indicators: list[Indicator] = []
    recommendations: list[str] = []


# -------------------------------------------------------------------- inputs
class ScanEmailRequest(BaseModel):
    email_id: str = Field(..., min_length=1, max_length=128)
    force: bool = False  # bypass cache


class ScanUrlRequest(BaseModel):
    url: HttpUrl
    context: dict[str, Any] | None = None


class RecheckRequest(BaseModel):
    threat_report_id: str = Field(..., min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=280)


# ------------------------------------------------------------------- outputs
class ProviderStatusOut(BaseModel):
    provider: str
    status: str
    latency_ms: int | None = None
    error_code: str | None = None


class ScoreBundleOut(BaseModel):
    threat_score: float
    trust_score: float
    security_score: float
    confidence: float


class IndicatorRollupOut(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    top: list[dict[str, Any]]


class ThreatReportOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(alias="_id")
    user_id: str
    email_id: str | None
    scan_generation: int
    channel: str
    triggered_by: str

    verdict: str
    threat_category: str
    severity: str
    scores: ScoreBundleOut
    risk_score: float

    scan_status: str
    providers: list[ProviderStatusOut]
    providers_ok: int
    providers_total: int

    summary: str
    why: list[str]
    evidence: list[dict[str, Any]]
    recommendations: list[str]
    recommended_action: str

    indicators: IndicatorRollupOut
    urls_analyzed: int
    domains_analyzed: int
    attachments_analyzed: int

    started_at: str | None
    completed_at: str | None
    duration_ms: int | None
    review_status: str

    created_at: datetime
    updated_at: datetime


class ScanAcceptedOut(BaseModel):
    threat_report_id: str
    scan_status: Literal["pending", "running", "completed"]
    cached: bool = False


class ProviderHealthOut(BaseModel):
    provider: str
    enabled: bool
    last_ok_at: datetime | None = None
    last_error_at: datetime | None = None
    error_rate_1h: float = 0.0
    p95_latency_ms: int | None = None
