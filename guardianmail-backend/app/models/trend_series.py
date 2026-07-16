"""Trend series — persisted time-bucketed metric history for a user.

Written by `analytics_platform.trend` tasks; read by the dashboard trend
endpoints. One row = one (user, metric, granularity, bucket_start).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document

Granularity = Literal["hour", "day", "week", "month"]


class TrendSeries(Document):
    user_id: str
    metric: str                 # e.g. "emails_total", "threats", "security_score"
    granularity: Granularity = "day"
    bucket_start: datetime
    value: float = 0.0
    dims: dict = Field(default_factory=dict)   # e.g. {"category": "phishing"}
    computed_at: datetime = Field(default_factory=now_utc)
