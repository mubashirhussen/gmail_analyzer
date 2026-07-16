"""EmailThread repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.email_thread import EmailThread
from app.repositories.base import BaseRepository


class EmailThreadsRepository(BaseRepository[EmailThread]):
    collection_name = "email_threads"
    model = EmailThread
    soft_delete = True

    async def upsert(
        self,
        *,
        user_id: str,
        thread_id: str,
        subject: str,
        snippet: str,
        participants: list[str],
        label_ids: list[str],
        last_message_at: datetime,
        has_unread: bool,
        has_attachments: bool,
    ) -> None:
        await self.col.update_one(
            {"user_id": user_id, "thread_id": thread_id},
            {
                "$set": {
                    "subject": subject,
                    "snippet": snippet,
                    "label_ids": label_ids,
                    "last_message_at": last_message_at,
                    "has_unread": has_unread,
                    "has_attachments": has_attachments,
                    "updated_at": now_utc(),
                },
                "$addToSet": {"participants": {"$each": participants}},
                "$inc": {"message_count": 1, "version": 1},
                "$setOnInsert": {
                    "user_id": user_id,
                    "thread_id": thread_id,
                    "created_at": now_utc(),
                    "deleted_at": None,
                },
            },
            upsert=True,
        )

    async def list_for_user(
        self, user_id: str, *, page: int = 1, page_size: int = 25
    ):
        return await self.paginate(
            {"user_id": user_id},
            page=page,
            page_size=page_size,
            sort=[("last_message_at", DESCENDING)],
        )
