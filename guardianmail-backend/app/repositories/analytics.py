"""Analytics snapshot repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import DESCENDING

from app.models.analytics import AnalyticsSnapshot
from app.repositories.base import BaseRepository


class AnalyticsRepository(BaseRepository[AnalyticsSnapshot]):
    collection_name = "analytics"
    model = AnalyticsSnapshot
    soft_delete = False  # snapshots are immutable time-series rows

    async def latest(self, user_id: str, period: str) -> AnalyticsSnapshot | None:
        return await self.find_one(
            {"user_id": user_id, "period": period}, sort=[("at", DESCENDING)]
        )

    async def range(
        self, user_id: str, period: str, *, since: datetime, until: datetime
    ) -> list[AnalyticsSnapshot]:
        return await self.find_many(
            {"user_id": user_id, "period": period, "at": {"$gte": since, "$lte": until}},
            limit=1000,
            sort=[("at", 1)],
        )

    async def upsert_snapshot(self, snap: AnalyticsSnapshot) -> None:
        payload = snap.model_dump(by_alias=True)
        await self.col.update_one(
            {"user_id": snap.user_id, "period": snap.period, "at": snap.at},
            {"$set": payload},
            upsert=True,
        )
