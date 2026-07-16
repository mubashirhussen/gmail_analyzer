"""Phase 18 — SOC DTOs."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "informational"]
IncidentStatus = Literal[
    "new", "investigating", "awaiting_review", "escalated", "resolved", "closed"
]


class IncidentCreate(BaseModel):
    user_id: str | None = None
    source: str = "manual"
    source_ref: str | None = None
    incident_type: str = "phishing"
    threat_category: str | None = None
    severity: Severity = "medium"
    confidence: float = 0.5
    risk_score: float = 50.0
    subject: str | None = None
    sender: str | None = None
    domain: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class IncidentTransition(BaseModel):
    status: IncidentStatus
    note: str | None = None
    resolution: str | None = None


class IncidentAssign(BaseModel):
    assigned_to: str


class CaseCreate(BaseModel):
    incident_id: str
    title: str
    priority: Literal["p1", "p2", "p3", "p4"] = "p3"
    owner: str | None = None


class CaseCommentIn(BaseModel):
    body: str
    author: str | None = None


class AlertAck(BaseModel):
    note: str | None = None


class IncidentOut(BaseModel):
    id: str = Field(alias="_id")
    user_id: str
    source: str
    incident_type: str
    severity: Severity
    status: IncidentStatus
    confidence: float
    risk_score: float
    subject: str | None = None
    sender: str | None = None
    domain: str | None = None
    urls: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    assigned_to: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"populate_by_name": True}


class DashboardOut(BaseModel):
    generated_at: datetime
    widgets: dict[str, Any]
    health: dict[str, Any]
    top_domains: list[dict[str, Any]] = Field(default_factory=list)
    recent_incidents: list[dict[str, Any]] = Field(default_factory=list)
    active_alerts: list[dict[str, Any]] = Field(default_factory=list)
