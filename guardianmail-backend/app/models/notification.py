"""User-facing notification document."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.models.base import Document

NotificationPriority = Literal["low", "normal", "high", "critical"]
NotificationType = Literal[
    "threat_detected",
    "device_new",
    "device_suspicious",
    "complaint_status",
    "evidence_ready",
    "scan_complete",
    "system",
]


class Notification(Document):
    user_id: str
    type: NotificationType
    priority: NotificationPriority = "normal"

    title: str
    body: str
    data: dict[str, Any] = Field(default_factory=dict)  # deep-link payload

    read: bool = False
    read_at: datetime | None = None
    dismissed: bool = False
    expires_at: datetime | None = None
