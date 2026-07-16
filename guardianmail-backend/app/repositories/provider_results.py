"""Repository for cached & audit provider responses."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.provider_result import ProviderResult
from app.repositories.base import BaseRepository


class ProviderResultRepository(BaseRepository[ProviderResult]):
    collection_name = "provider_results"
    model = ProviderResult
    soft_delete = False  # TTL-driven; no tombstoning

    async def cached(
        self, *, provider: str, artifact_hash: str, ttl_seconds: int
    ) -> ProviderResult | None:
        floor = now_utc() - timedelta(seconds=ttl_seconds)
        return await self.find_one(
            {
                "provider": provider,
                "artifact_hash": artifact_hash,
                "status": "ok",
                "created_at": {"$gte": floor},
            },
            sort=[("created_at", DESCENDING)],
        )

    async def for_report(self, threat_report_id: str) -> list[ProviderResult]:
        return await self.find_many(
            {"threat_report_id": threat_report_id},
            limit=500,
            sort=[("created_at", 1)],
        )

    async def provider_health(self, provider: str, *, minutes: int = 60) -> dict[str, Any]:
        since = now_utc() - timedelta(minutes=minutes)
        pipeline = [
            {"$match": {"provider": provider, "created_at": {"$gte": since}}},
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1},
                    "avg_latency_ms": {"$avg": "$latency_ms"},
                }
            },
        ]
        rows = await self.aggregate(pipeline)
        total = sum(r["count"] for r in rows) or 1
        errors = sum(r["count"] for r in rows if r["_id"] != "ok")
        return {
            "provider": provider,
            "error_rate": errors / total,
            "total": total,
            "by_status": {r["_id"]: r["count"] for r in rows},
        }
