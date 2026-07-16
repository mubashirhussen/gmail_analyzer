"""AI Analysis Engine — request / response DTOs (Module 6)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AIAnalyzeRequest(BaseModel):
    threat_report_id: str
    force: bool = False  # bypass cached AI report
    channel: Literal["email", "url", "manual", "recheck"] = "email"


class ConfidenceDTO(BaseModel):
    overall: float
    evidence_strength: float
    provider_agreement: float
    model_confidence: float
    data_completeness: float
    reliability: float


class RecommendationDTO(BaseModel):
    action: str
    priority: str
    rationale: str = ""
    category: str = "immediate"


class EvidenceRefDTO(BaseModel):
    category: str
    detail: str
    severity: str
    weight: float


class AIReportDTO(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(alias="_id")
    user_id: str
    threat_report_id: str
    email_id: str | None = None
    status: str
    verdict: str
    attack_type: str | None = None
    likely_objective: str | None = None
    risk_level: str
    trust_score_adjustment: float

    threat_summary: str
    executive_summary: str
    detailed_explanation: str
    reasoning: list[str]
    evidence_used: list[EvidenceRefDTO]
    possible_consequences: list[str]
    user_impact: str

    confidence: ConfidenceDTO
    recommendations: list[RecommendationDTO]
    immediate_actions: list[str]
    long_term_recommendations: list[str]
    educational_tips: list[str]
    technical_notes: list[str]

    model_provider: str
    model_name: str
    model_version: str
    prompt_version: str
    prompt_hash: str
    validation_passed: bool
    hallucination_score: float

    created_at: datetime
    completed_at: str | None = None
    duration_ms: int | None = None


class AIModelInfo(BaseModel):
    provider: str
    name: str
    version: str
    is_default: bool = False
    supports_json_mode: bool = True
    max_prompt_tokens: int
