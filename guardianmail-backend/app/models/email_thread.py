"""Gmail thread document — conversation-level rollup."""
from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.models.base import Document


class EmailThread(Document):
    user_id: str
    thread_id: str                    # Gmail threadId
    subject: str = ""
    participants: list[str] = Field(default_factory=list)
    message_count: int = 0
    last_message_at: datetime | None = None
    label_ids: list[str] = Field(default_factory=list)
    snippet: str = ""
    has_unread: bool = False
    has_attachments: bool = False
