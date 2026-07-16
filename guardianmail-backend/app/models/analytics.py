"""Analytics snapshot document.

Immutable time-bucketed rollup of a user's threat/security posture.
Written by the analytics worker; read by dashboards and reports.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document

Period = Literal["hour", "day", "week", "month"]


class AnalyticsSnapshot(Document):
    user_id: str
    period: Period = "day"
    at: datetime = Field(default_factory=now_utc)

    threat_score: int = 0       # 0-100 (higher = more incoming threats)
    security_score: int = 0     # 0-100 (higher = better hygiene)
    privacy_score: int = 0
    trust_score: int = 0

    emails_total: int = 0
    emails_scanned: int = 0
    threats_detected: int = 0

    counts: dict = Field(default_factory=dict)          # {safe, suspicious, phishing, fraud}
    top_categories: list[dict] = Field(default_factory=list)  # [{category, count}]
    top_sender_domains: list[dict] = Field(default_factory=list)
    risk_buckets: list[dict] = Field(default_factory=list)    # from $bucket agg
