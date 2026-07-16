"""Phase 18 — Enterprise SOC persistence models.

Additive, non-invasive collections. Nothing here mutates prior modules; SOC
consumes events emitted by the rest of the platform and stores its own
incidents, cases, alerts, audit trail, health snapshots, and reports.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


Severity = Literal["critical", "high", "medium", "low", "informational"]
IncidentStatus = Literal[
    "new", "investigating", "awaiting_review", "escalated", "resolved", "closed"
]
CasePriority = Literal["p1", "p2", "p3", "p4"]


class IncidentTimelineEntry(Document):
    """One immutable step in an incident's timeline."""

    incident_id: str
    step: str                              # e.g. "email_received", "ai_analysis"
    actor: str = "system"                  # "system" or user_id
    summary: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class Incident(Document):
    """A correlated security event promoted from a detection/threat/AI signal."""

    user_id: str
    source: str = "detection"              # detection|threat|ai|manual|alert
    source_ref: str | None = None          # id of the source doc

    incident_type: str = "phishing"        # phishing|bec|malware|fraud|policy
    threat_category: str | None = None
    severity: Severity = "medium"
    confidence: float = 0.0                # 0..1
    risk_score: float = 0.0                # 0..100

    subject: str | None = None
    sender: str | None = None
    domain: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)

    status: IncidentStatus = "new"
    assigned_to: str | None = None
    tags: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    resolution: str | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None


class Case(Document):
    """A case wraps an incident for analyst-driven investigation."""

    incident_id: str
    user_id: str
    owner: str | None = None
    priority: CasePriority = "p3"
    title: str
    notes: list[dict[str, Any]] = Field(default_factory=list)
    comments: list[dict[str, Any]] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)


class Alert(Document):
    """A discrete alert raised by SOC monitors."""

    kind: str                              # critical_threat|redis_failure|...
    severity: Severity = "high"
    title: str
    message: str = ""
    user_id: str | None = None
    incident_id: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None


class AuditLogEntry(Document):
    """Tamper-evident audit log entry for SOC-observable actions."""

    actor: str                             # user_id or "system"
    action: str                            # e.g. "incident.transition"
    entity_type: str | None = None
    entity_id: str | None = None
    user_id: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    ip: str | None = None
    request_id: str | None = None


class SystemHealthSnapshot(Document):
    """Point-in-time snapshot of platform component health."""

    component: str                         # api|mongo|redis|celery|ai|ti|nginx
    status: str = "healthy"                # healthy|degraded|down
    latency_ms: float | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=now_utc)


class SOCReport(Document):
    """Generated SOC report (daily/weekly/monthly/incident)."""

    kind: str                              # daily|weekly|monthly|incident|adhoc
    period_start: datetime
    period_end: datetime
    generated_by: str = "system"
    summary: dict[str, Any] = Field(default_factory=dict)
    sections: list[dict[str, Any]] = Field(default_factory=list)
