"""Security event repository."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.security_event import SecurityEvent
from app.repositories.base import BaseRepository


class SecurityEventRepository(BaseRepository[SecurityEvent]):
    collection_name = "security_events"
    model = SecurityEvent
    soft_delete = False

    async def list_for_user(
        self, user_id: str, *, page: int = 1, page_size: int = 25
    ):
        return await self.paginate(
            {"user_id": user_id},
            page=page,
            page_size=page_size,
            sort=[("created_at", DESCENDING)],
        )

    async def recent_by_kind(self, kind: str, hours: int = 24, limit: int = 100) -> list[SecurityEvent]:
        since = now_utc() - timedelta(hours=hours)
        return await self.find_many(
            {"kind": kind, "created_at": {"$gte": since}},
            limit=limit,
            sort=[("created_at", DESCENDING)],
        )

    async def severity_counts(self, user_id: str, days: int = 30) -> list[dict[str, Any]]:
        since = now_utc() - timedelta(days=days)
        pipeline = [
            {"$match": {"user_id": user_id, "created_at": {"$gte": since}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
        return await self.aggregate(pipeline)
