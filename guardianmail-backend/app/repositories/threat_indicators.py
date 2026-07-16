"""Threat indicator (IOC) repository."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING, UpdateOne

from app.models.threat_indicator import ThreatIndicator
from app.repositories.base import BaseRepository


class ThreatIndicatorRepository(BaseRepository[ThreatIndicator]):
    collection_name = "threat_indicators"
    model = ThreatIndicator
    soft_delete = True

    async def for_report(self, threat_report_id: str) -> list[ThreatIndicator]:
        return await self.find_many({"threat_report_id": threat_report_id}, limit=500)

    async def by_value_hash(self, value_hash: str, *, limit: int = 25) -> list[ThreatIndicator]:
        return await self.find_many(
            {"value_hash": value_hash}, limit=limit, sort=[("created_at", DESCENDING)]
        )

    async def bulk_upsert(self, items: list[ThreatIndicator]) -> int:
        if not items:
            return 0
        ops = [
            UpdateOne(
                {
                    "threat_report_id": i.threat_report_id,
                    "kind": i.kind,
                    "value_hash": i.value_hash,
                },
                {"$set": i.model_dump(by_alias=True)},
                upsert=True,
            )
            for i in items
        ]
        res = await self.bulk_write(ops)
        return (res.upserted_count if res else 0) + (res.modified_count if res else 0)

    async def global_frequency(self, kind: str, *, limit: int = 25) -> list[dict[str, Any]]:
        pipeline = [
            {"$match": {"kind": kind, "deleted_at": None}},
            {"$group": {"_id": "$value_hash", "count": {"$sum": 1}, "sample": {"$first": "$value"}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
        ]
        return await self.aggregate(pipeline)
