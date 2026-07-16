"""Notification repository."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.notification import Notification
from app.repositories.base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    collection_name = "notifications"
    model = Notification
    soft_delete = False  # short-lived rows, TTL handles cleanup

    async def list_for_user(
        self,
        user_id: str,
        *,
        unread_only: bool = False,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if unread_only:
            f["read"] = False
        return await self.paginate(
            f, page=page, page_size=page_size, sort=[("created_at", DESCENDING)]
        )

    async def unread_count(self, user_id: str) -> int:
        return await self.count({"user_id": user_id, "read": False, "dismissed": False})

    async def mark_read(self, user_id: str, ids: list[str]) -> int:
        res = await self.col.update_many(
            {"_id": {"$in": ids}, "user_id": user_id, "read": False},
            {"$set": {"read": True, "read_at": now_utc(), "updated_at": now_utc()}},
        )
        return res.modified_count

    async def mark_all_read(self, user_id: str) -> int:
        res = await self.col.update_many(
            {"user_id": user_id, "read": False},
            {"$set": {"read": True, "read_at": now_utc(), "updated_at": now_utc()}},
        )
        return res.modified_count
