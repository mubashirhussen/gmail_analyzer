"""LabelService — synchronise Gmail label catalogue for a user."""
from __future__ import annotations

from typing import Any

from app.database.mongodb import get_db
from app.models.email_label import EmailLabel
from app.repositories.email_labels import EmailLabelsRepository
from app.services.gmail.client import build_service, get_label, list_labels


class LabelService:
    async def sync(self, *, user_id: str, refresh_token_enc: str) -> int:
        service = build_service(refresh_token_enc)
        labels = list_labels(service)
        detailed = [get_label(service, l["id"]) for l in labels]
        docs = [self._to_doc(user_id, l) for l in detailed]
        repo = EmailLabelsRepository(get_db())
        await repo.replace_all(user_id, docs)
        return len(docs)

    @staticmethod
    def _to_doc(user_id: str, raw: dict[str, Any]) -> EmailLabel:
        color = raw.get("color") or {}
        return EmailLabel(
            user_id=user_id,
            label_id=raw["id"],
            name=raw["name"],
            type="system" if raw.get("type") == "system" else "user",
            messages_total=int(raw.get("messagesTotal") or 0),
            messages_unread=int(raw.get("messagesUnread") or 0),
            threads_total=int(raw.get("threadsTotal") or 0),
            threads_unread=int(raw.get("threadsUnread") or 0),
            color_bg=color.get("backgroundColor"),
            color_fg=color.get("textColor"),
        )


label_service = LabelService()
