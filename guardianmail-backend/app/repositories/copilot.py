"""Copilot repositories — conversations, messages, prompt/response audit."""
from __future__ import annotations

from typing import Any

from pymongo import ASCENDING, DESCENDING

from app.core.clock import now_utc
from app.models.copilot import CopilotConversation, CopilotMessage
from app.repositories.base import BaseRepository


class ConversationRepository(BaseRepository[CopilotConversation]):
    collection_name = "copilot_conversations"
    model = CopilotConversation
    soft_delete = True

    async def list_for_user(self, user_id: str, *, page: int = 1, page_size: int = 25):
        return await self.paginate(
            {"user_id": user_id, "archived": False},
            page=page,
            page_size=page_size,
            sort=[("last_message_at", DESCENDING)],
        )

    async def touch(self, conversation_id: str) -> None:
        await self.update_one(
            {"_id": conversation_id},
            {"$set": {"last_message_at": now_utc()}, "$inc": {"message_count": 1}},
        )

    async def archive_for_user(self, user_id: str) -> int:
        res = await self.collection.update_many(
            {"user_id": user_id, "archived": False},
            {"$set": {"archived": True, "updated_at": now_utc()}},
        )
        return int(res.modified_count or 0)


class MessageRepository(BaseRepository[CopilotMessage]):
    collection_name = "copilot_messages"
    model = CopilotMessage
    soft_delete = False

    async def list_for_conversation(
        self, conversation_id: str, *, limit: int = 50
    ) -> list[CopilotMessage]:
        cur = self.collection.find(
            {"conversation_id": conversation_id}
        ).sort("created_at", ASCENDING).limit(limit)
        docs = await cur.to_list(length=limit)
        return [self.model(**d) for d in docs]

    async def delete_for_conversation(self, conversation_id: str) -> int:
        res = await self.collection.delete_many({"conversation_id": conversation_id})
        return int(res.deleted_count or 0)

    async def delete_for_user(self, user_id: str) -> int:
        res = await self.collection.delete_many({"user_id": user_id})
        return int(res.deleted_count or 0)
