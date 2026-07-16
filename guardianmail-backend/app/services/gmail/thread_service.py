"""ThreadService — maintain Gmail conversation rollups."""
from __future__ import annotations

from datetime import datetime

from app.database.mongodb import get_db
from app.models.email import EmailDoc
from app.repositories.email_threads import EmailThreadsRepository


class ThreadService:
    async def upsert_from_email(self, doc: EmailDoc) -> None:
        if not doc.thread_id:
            return
        participants = [a for a in [doc.sender_email, *doc.recipients, *doc.cc] if a]
        repo = EmailThreadsRepository(get_db())
        await repo.upsert(
            user_id=doc.user_id,
            thread_id=doc.thread_id,
            subject=doc.subject,
            snippet=doc.snippet,
            participants=list({p.lower() for p in participants})[:50],
            label_ids=doc.labels,
            last_message_at=doc.received_at,
            has_unread=doc.is_unread,
            has_attachments=doc.has_attachments,
        )


thread_service = ThreadService()
