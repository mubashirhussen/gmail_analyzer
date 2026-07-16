"""Audit log — request-scoped trail of every mutating action."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


class AuditLog(Document):
    at: datetime = Field(default_factory=now_utc)
    request_id: str = ""
    user_id: str | None = None
    session_id: str | None = None
    device_id: str | None = None
    ip: str = ""
    user_agent: str = ""
    actor: str = "user"                  # user | system | worker
    action: str                          # e.g. "auth.login", "device.trust"
    resource: str | None = None
    outcome: str = "success"             # success | failure
    meta: dict[str, Any] = Field(default_factory=dict)
