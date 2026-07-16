"""Session document — one row per active login."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


class Session(Document):
    user_id: str
    device_id: str
    refresh_jti: str                     # current head of the rotation chain
    ip: str = ""
    user_agent: str = ""
    remember_me: bool = False

    issued_at: datetime = Field(default_factory=now_utc)
    last_active_at: datetime = Field(default_factory=now_utc)
    expires_at: datetime
    revoked_at: datetime | None = None
    revoke_reason: str | None = None

    status: Literal["active", "revoked", "expired"] = "active"
