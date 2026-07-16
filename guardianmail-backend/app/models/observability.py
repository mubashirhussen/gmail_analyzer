"""Phase 19 — observability persistence models."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


Severity = Literal["critical", "high", "medium", "low", "informational"]


class TelemetrySpan(Document):
    """Persisted span record for the trace explorer."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    name: str
    service: str = "guardianmail-api"
    kind: str = "internal"
    started_at: datetime = Field(default_factory=now_utc)
    duration_ms: float = 0.0
    status: str = "ok"                     # ok|error
    attributes: dict[str, Any] = Field(default_factory=dict)


class OperationalIncident(Document):
    """Ops-side incident distinct from SOC's security incidents."""

    kind: str                              # api_down|db_down|redis_down|latency|error_rate|...
    severity: Severity = "high"
    title: str
    summary: str = ""
    affected: list[str] = Field(default_factory=list)
    root_cause: str | None = None
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    suggested_resolution: str | None = None
    status: str = "open"                   # open|acknowledged|mitigated|resolved
    recovered_at: datetime | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ObservabilityAlert(Document):
    """Alerts observed via Prometheus/AlertManager or internal probes."""

    rule: str
    severity: Severity = "high"
    component: str
    summary: str
    description: str = ""
    fingerprint: str
    active: bool = True
    fired_at: datetime = Field(default_factory=now_utc)
    resolved_at: datetime | None = None
    labels: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)


class MetricSnapshot(Document):
    """Point-in-time roll-up of key operational metrics."""

    window: str = "1m"                     # 1m|5m|1h|1d
    captured_at: datetime = Field(default_factory=now_utc)
    values: dict[str, Any] = Field(default_factory=dict)
