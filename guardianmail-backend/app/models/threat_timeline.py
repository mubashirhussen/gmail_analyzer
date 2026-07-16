"""Threat report timeline events.

An append-only stream of engine milestones for a single ThreatReport:
extraction started, provider X finished, aggregator computed score,
report generated, etc. Used by the frontend to show live progress and
by SRE to reconstruct the scan lifecycle after the fact.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.models.base import Document

EventKind = Literal[
    "scan_started",
    "extraction_done",
    "provider_dispatched",
    "provider_completed",
    "provider_failed",
    "indicator_recorded",
    "score_computed",
    "verdict_assigned",
    "scan_completed",
    "scan_failed",
    "recheck_requested",
]


class ThreatTimelineEvent(Document):
    threat_report_id: str
    user_id: str
    kind: EventKind
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    sequence: int = 0  # per-report ordering; monotonic
