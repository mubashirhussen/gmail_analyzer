"""Phase 19 — observability repositories."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import DESCENDING

from app.models.observability import (
    MetricSnapshot,
    ObservabilityAlert,
    OperationalIncident,
    TelemetrySpan,
)
from app.repositories.base import BaseRepository


class TelemetryRepository(BaseRepository[TelemetrySpan]):
    collection_name = "obs_spans"
    model = TelemetrySpan
    soft_delete = False

    async def for_trace(self, trace_id: str) -> list[dict]:
        cur = self.col.find({"trace_id": trace_id}).sort("started_at", 1)
        return [d async for d in cur]

    async def recent(self, *, limit: int = 50) -> list[dict]:
        cur = self.col.find({}).sort("started_at", DESCENDING).limit(limit)
        return [d async for d in cur]


class ObservabilityAlertRepository(BaseRepository[ObservabilityAlert]):
    collection_name = "obs_alerts"
    model = ObservabilityAlert
    soft_delete = False

    async def active(self, *, limit: int = 100) -> list[dict]:
        cur = self.col.find({"active": True}).sort("fired_at", DESCENDING).limit(limit)
        return [d async for d in cur]


class OpsIncidentRepository(BaseRepository[OperationalIncident]):
    collection_name = "obs_incidents"
    model = OperationalIncident
    soft_delete = True

    async def open_incidents(self) -> list[dict]:
        cur = self.col.find({"status": {"$ne": "resolved"}, "deleted_at": None})
        return [d async for d in cur.sort("created_at", DESCENDING)]


class MetricsSnapshotRepository(BaseRepository[MetricSnapshot]):
    collection_name = "obs_metric_snapshots"
    model = MetricSnapshot
    soft_delete = False

    async def latest(self, *, window: str = "1m") -> dict | None:
        return await self.find_one(
            {"window": window}, sort=[("captured_at", DESCENDING)],
        )
