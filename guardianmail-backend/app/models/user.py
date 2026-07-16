"""User document."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import EmailStr, Field

from app.core.clock import now_utc
from app.models.base import Document


class User(Document):
    email: EmailStr
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    locale: str | None = None

    # oauth linkage
    google_sub: str | None = None

    # security
    status: Literal["active", "locked", "disabled"] = "active"
    failed_login_count: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    last_login_ip: str | None = None
    concurrent_session_limit: int = 10

    # passcode (optional application lock)
    passcode_hash: str | None = None
    passcode_updated_at: datetime | None = None
    passcode_failed_count: int = 0
    passcode_locked_until: datetime | None = None
