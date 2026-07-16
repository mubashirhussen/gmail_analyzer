"""Dashboard cache metadata — index of cached dashboard payloads in Redis.

The actual payload lives in Redis under keys built by
`analytics_platform.redis_keys`. This document tracks freshness, hits, and
computation cost so ops can reason about hot users without scanning Redis.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document

CacheScope = Literal[
    "overview", "security", "threats", "emails",
    "domains", "ai", "ocr", "complaints", "trends",
]


class DashboardCacheEntry(Document):
    user_id: str
    scope: CacheScope
    time_filter: str = "last_30_days"
    key: str
    ttl_s: int = 300
    computed_at: datetime = Field(default_factory=now_utc)
    compute_ms: int = 0
    hits: int = 0
    stale_at: datetime | None = None
