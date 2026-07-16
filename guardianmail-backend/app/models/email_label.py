"""Gmail label document — mirrors both system and user labels."""
from __future__ import annotations

from typing import Literal

from app.models.base import Document

LabelType = Literal["system", "user"]


class EmailLabel(Document):
    user_id: str
    label_id: str                     # Gmail label id
    name: str
    type: LabelType = "user"
    messages_total: int = 0
    messages_unread: int = 0
    threads_total: int = 0
    threads_unread: int = 0
    color_bg: str | None = None
    color_fg: str | None = None
