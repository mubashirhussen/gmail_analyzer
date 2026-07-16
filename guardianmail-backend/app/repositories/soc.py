"""Phase 18 — SOC repositories."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.soc import (
    Alert,
    AuditLogEntry,
    Case,
    Incident,
    IncidentTimelineEntry,
    SOCReport,
    SystemHealthSnapshot,
)
from app.repositories.base import BaseRepository


class IncidentRepository(BaseRepository[Incident]):
    collection_name = "soc_incidents"
    model = Incident
    soft_delete = True

    async def list_filtered(
        self,
        *,
        user_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        incident_type: str | None = None,
        sender: str | None = None,
        domain: str | None = None,
        since: datetime | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {}
        if user_id:
            f["user_id"] = user_id
        if severity:
            f["severity"] = severity
        if status:
            f["status"] = status
        if incident_type:
            f["incident_type"] = incident_type
        if sender:
            f["sender"] = sender.lower()
        if domain:
            f["domain"] = domain.lower()
        if since:
            f["created_at"] = {"$gte": since}
        return await self.paginate(
            f, page=page, page_size=page_size,
            sort=[("severity", 1), ("created_at", DESCENDING)],
        )

    async def counts_by(self, field: str, *, since: datetime | None = None) -> dict[str, int]:
        match: dict[str, Any] = {"deleted_at": None}
        if since:
            match["created_at"] = {"$gte": since}
        rows = await self.aggregate(
            [{"$match": match}, {"$group": {"_id": f"${field}", "n": {"$sum": 1}}}]
        )
        return {r["_id"] or "unknown": int(r["n"]) for r in rows}

    async def top_domains(self, *, since: datetime | None = None, limit: int = 10):
        match: dict[str, Any] = {"deleted_at": None, "domain": {"$ne": None}}
        if since:
            match["created_at"] = {"$gte": since}
        return await self.aggregate(
            [
                {"$match": match},
                {"$group": {"_id": "$domain", "n": {"$sum": 1},
                            "avg_score": {"$avg": "$risk_score"}}},
                {"$sort": {"n": -1}},
                {"$limit": limit},
                {"$project": {"domain": "$_id", "count": "$n",
                              "avg_risk_score": "$avg_score", "_id": 0}},
            ]
        )


class TimelineRepository(BaseRepository[IncidentTimelineEntry]):
    collection_name = "soc_incident_timeline"
    model = IncidentTimelineEntry
    soft_delete = False

    async def for_incident(self, incident_id: str) -> list[dict]:
        cur = self.col.find({"incident_id": incident_id}).sort("created_at", 1)
        return [d async for d in cur]


class CaseRepository(BaseRepository[Case]):
    collection_name = "soc_cases"
    model = Case
    soft_delete = True

    async def for_incident(self, incident_id: str) -> dict | None:
        return await self.find_one({"incident_id": incident_id})


class AlertRepository(BaseRepository[Alert]):
    collection_name = "soc_alerts"
    model = Alert
    soft_delete = True

    async def active(self, *, limit: int = 50) -> list[dict]:
        cur = (
            self.col.find({"acknowledged": False, "deleted_at": None})
            .sort("created_at", DESCENDING)
            .limit(limit)
        )
        return [d async for d in cur]


class AuditRepository(BaseRepository[AuditLogEntry]):
    collection_name = "soc_audit_log"
    model = AuditLogEntry
    soft_delete = False


class HealthRepository(BaseRepository[SystemHealthSnapshot]):
    collection_name = "soc_system_health"
    model = SystemHealthSnapshot
    soft_delete = False

    async def latest(self) -> dict[str, dict]:
        rows = await self.aggregate(
            [
                {"$sort": {"checked_at": -1}},
                {"$group": {"_id": "$component", "doc": {"$first": "$$ROOT"}}},
            ]
        )
        return {r["_id"]: r["doc"] for r in rows}


class ReportRepository(BaseRepository[SOCReport]):
    collection_name = "soc_reports"
    model = SOCReport
    soft_delete = True


def since_hours(hours: int) -> datetime:
    return now_utc() - timedelta(hours=hours)
