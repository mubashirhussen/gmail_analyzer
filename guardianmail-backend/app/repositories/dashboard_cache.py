"""Dashboard cache-metadata repository."""
from __future__ import annotations

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.dashboard_cache import DashboardCacheEntry
from app.repositories.base import BaseRepository


class DashboardCacheRepository(BaseRepository[DashboardCacheEntry]):
    collection_name = "dashboard_cache"
    model = DashboardCacheEntry
    soft_delete = False

    async def upsert(self, entry: DashboardCacheEntry) -> None:
        payload = entry.model_dump(by_alias=True)
        await self.col.update_one(
            {"user_id": entry.user_id, "scope": entry.scope, "time_filter": entry.time_filter},
            {"$set": payload, "$inc": {"hits": 0}},
            upsert=True,
        )

    async def record_hit(self, user_id: str, scope: str, time_filter: str) -> None:
        await self.col.update_one(
            {"user_id": user_id, "scope": scope, "time_filter": time_filter},
            {"$inc": {"hits": 1}, "$set": {"updated_at": now_utc()}},
        )

    async def recent(self, user_id: str, limit: int = 20) -> list[DashboardCacheEntry]:
        return await self.find_many(
            {"user_id": user_id}, sort=[("computed_at", DESCENDING)], limit=limit
        )
