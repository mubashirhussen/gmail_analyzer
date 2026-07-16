"""Threat report repository."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.threat import ThreatReport
from app.repositories.base import BaseRepository


class ThreatReportRepository(BaseRepository[ThreatReport]):
    collection_name = "threats"
    model = ThreatReport
    soft_delete = True

    async def latest_for_email(self, email_id: str) -> ThreatReport | None:
        return await self.find_one({"email_id": email_id}, sort=[("created_at", DESCENDING)])

    async def list_for_user(
        self, user_id: str, *, min_risk: float | None = None, page: int = 1, page_size: int = 25
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if min_risk is not None:
            f["risk_score"] = {"$gte": min_risk}
        return await self.paginate(f, page=page, page_size=page_size)

    async def category_breakdown(self, user_id: str, days: int = 30) -> list[dict]:
        since = now_utc() - timedelta(days=days)
        pipeline = [
            {"$match": {"user_id": user_id, "created_at": {"$gte": since}, "deleted_at": None}},
            {"$group": {"_id": "$threat_category", "count": {"$sum": 1}, "avg_risk": {"$avg": "$risk_score"}}},
            {"$sort": {"count": -1}},
        ]
        return await self.aggregate(pipeline)

    async def risk_distribution(self, user_id: str, days: int = 30) -> list[dict]:
        since = now_utc() - timedelta(days=days)
        pipeline = [
            {"$match": {"user_id": user_id, "created_at": {"$gte": since}, "deleted_at": None}},
            {
                "$bucket": {
                    "groupBy": "$risk_score",
                    "boundaries": [0, 20, 40, 60, 80, 101],
                    "default": "other",
                    "output": {"count": {"$sum": 1}},
                }
            },
        ]
        return await self.aggregate(pipeline)
