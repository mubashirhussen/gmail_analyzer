"""ConversationService — short-lived investigation memory.

Conversations are always scoped to a GuardianMail artifact (threat/email/
evidence pack). Memory is intentionally short: only the last N turns are
retained for continuity; nothing about the user is remembered permanently.
"""
from __future__ import annotations

from typing import Any

from app.database.mongodb import get_db
from app.models.copilot import CopilotConversation, CopilotMessage
from app.repositories.copilot import ConversationRepository, MessageRepository

MAX_TURNS = 6


class ConversationService:
    def _repos(self) -> tuple[ConversationRepository, MessageRepository]:
        db = get_db()
        return ConversationRepository(db), MessageRepository(db)

    async def get_or_create(
        self, *, user_id: str, conversation_id: str | None,
        scope: dict[str, Any], provider: str | None,
    ) -> CopilotConversation:
        convs, _ = self._repos()
        if conversation_id:
            existing = await convs.find_by_id(conversation_id)
            if existing and existing.get("user_id") == user_id:
                return CopilotConversation(**existing)
        conv = CopilotConversation(
            user_id=user_id, scope=scope, provider=provider,
            title=(scope.get("threat_id") or scope.get("email_id")
                   or scope.get("scan_id") or "investigation")[:80],
        )
        await convs.insert_one(conv.to_mongo())
        return conv

    async def recent_turns(self, conversation_id: str) -> list[dict[str, str]]:
        _, msgs = self._repos()
        messages = await msgs.list_for_conversation(conversation_id, limit=MAX_TURNS * 2)
        return [
            {"role": m.role, "content": (m.content or "")[:2000]}
            for m in messages
        ]

    async def append(self, msg: CopilotMessage) -> None:
        convs, msgs = self._repos()
        await msgs.insert_one(msg.to_mongo())
        await convs.touch(msg.conversation_id)

    async def list_conversations(self, user_id: str, *, page: int = 1, page_size: int = 25):
        convs, _ = self._repos()
        return await convs.list_for_user(user_id, page=page, page_size=page_size)

    async def delete_conversation(self, *, user_id: str, conversation_id: str) -> bool:
        convs, msgs = self._repos()
        existing = await convs.find_by_id(conversation_id)
        if not existing or existing.get("user_id") != user_id:
            return False
        await msgs.delete_for_conversation(conversation_id)
        await convs.soft_delete({"_id": conversation_id})
        return True

    async def clear_user_history(self, user_id: str) -> dict[str, int]:
        convs, msgs = self._repos()
        deleted_msgs = await msgs.delete_for_user(user_id)
        archived = await convs.archive_for_user(user_id)
        return {"messages_deleted": deleted_msgs, "conversations_archived": archived}


conversation_service = ConversationService()
