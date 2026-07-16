"""Security event — actionable, notifiable security signal."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


SecuritySeverity = Literal["info", "low", "medium", "high", "critical"]

SecurityKind = Literal[
    "login_success", "login_failure",
    "logout", "logout_all",
    "token_refreshed", "token_revoked", "token_reuse",
    "session_expired", "session_revoked",
    "device_new", "device_removed", "device_trusted",
    "oauth_failure",
    "passcode_set", "passcode_changed", "passcode_failure", "passcode_locked",
    "account_locked", "account_unlocked",
    "rate_limited",
]


class SecurityEvent(Document):
    user_id: str | None = None
    at: datetime = Field(default_factory=now_utc)
    kind: SecurityKind
    severity: SecuritySeverity = "info"
    ip: str = ""
    device_id: str | None = None
    session_id: str | None = None
    message: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)
    notified: bool = False
