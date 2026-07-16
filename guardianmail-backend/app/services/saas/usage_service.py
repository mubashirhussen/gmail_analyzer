"""Usage tracking (Phase 20).

Deterministic in-memory aggregator. In production the same interface is
backed by a Mongo `saas_usage` collection with a per-tenant/day compound
key; the pure Python implementation keeps unit tests fast.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Dict, Iterable

METRICS: tuple = (
    "emails_scanned", "threat_scans", "ai_requests", "ocr_requests",
    "storage_mb", "bandwidth_mb", "api_calls",
    "complaint_generations", "evidence_downloads",
)


def _day(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m-%d")


def _month(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m")


class UsageService:
    def __init__(self):
        # (tenant_id, period_key, metric) -> int
        self._counters: Dict[tuple, int] = {}

    def record(self, tenant_id: str, metric: str, amount: int = 1,
               *, at: datetime | None = None) -> None:
        if metric not in METRICS:
            raise ValueError(f"unknown usage metric: {metric}")
        if amount <= 0:
            return
        for period in (_day(at), _month(at)):
            key = (tenant_id, period, metric)
            self._counters[key] = self._counters.get(key, 0) + int(amount)

    def get(self, tenant_id: str, metric: str, period: str) -> int:
        return int(self._counters.get((tenant_id, period, metric), 0))

    def snapshot(self, tenant_id: str, *, at: datetime | None = None) -> dict:
        day, month = _day(at), _month(at)
        return {
            "tenant_id": tenant_id,
            "day": day,
            "month": month,
            "daily": {m: self.get(tenant_id, m, day) for m in METRICS},
            "monthly": {m: self.get(tenant_id, m, month) for m in METRICS},
            "generated_at": (at or datetime.now(timezone.utc)).isoformat(),
        }

    def aggregate(self, tenant_ids: Iterable[str], period: str,
                  metric: str) -> int:
        return sum(self.get(t, metric, period) for t in tenant_ids)

    @staticmethod
    def today() -> str:
        return _day()

    @staticmethod
    def month() -> str:
        return _month()
