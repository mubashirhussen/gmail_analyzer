"""Device document — one row per (user, fingerprint)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


class Device(Document):
    user_id: str
    fingerprint: str
    label: str = ""
    browser: str = ""
    os: str = ""
    device_type: str = "desktop"        # desktop | mobile | tablet | bot | unknown
    ip: str = ""
    location: str = ""                  # coarse "City, CC" from IP lookup
    first_seen_at: datetime = Field(default_factory=now_utc)
    last_seen_at: datetime = Field(default_factory=now_utc)
    trusted: bool = False
    risk: Literal["low", "medium", "high"] = "low"
    revoked_at: datetime | None = None
