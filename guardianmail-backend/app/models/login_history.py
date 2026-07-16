"""Login history — every attempt, success or failure."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


class LoginHistory(Document):
    user_id: str | None = None
    email: str | None = None
    at: datetime = Field(default_factory=now_utc)
    ip: str = ""
    user_agent: str = ""
    browser: str = ""
    os: str = ""
    device_id: str | None = None
    session_id: str | None = None
    location: str = ""
    method: Literal["google", "refresh", "passcode"] = "google"
    outcome: Literal["success", "failure"] = "success"
    failure_reason: str | None = None
