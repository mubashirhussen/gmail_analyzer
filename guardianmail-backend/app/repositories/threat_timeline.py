"""Threat report timeline repository."""
from __future__ import annotations

from pymongo import ASCENDING

from app.models.threat_timeline import ThreatTimelineEvent
from app.repositories.base import BaseRepository


class ThreatTimelineRepository(BaseRepository[ThreatTimelineEvent]):
    collection_name = "threat_timeline"
    model = ThreatTimelineEvent
    soft_delete = False

    async def for_report(self, threat_report_id: str) -> list[ThreatTimelineEvent]:
        return await self.find_many(
            {"threat_report_id": threat_report_id},
            limit=500,
            sort=[("sequence", ASCENDING), ("created_at", ASCENDING)],
        )

    async def next_sequence(self, threat_report_id: str) -> int:
        n = await self.count({"threat_report_id": threat_report_id})
        return int(n) + 1
