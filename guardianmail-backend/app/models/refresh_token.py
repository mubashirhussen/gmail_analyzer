"""Refresh token document. One row per issued refresh token JTI.

Rotation means: on refresh we mark the old token `rotated_at` + `replaced_by`
and issue a new one. Presenting a rotated (or revoked) token = reuse attack.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.core.clock import now_utc
from app.models.base import Document


class RefreshToken(Document):
    jti: str
    user_id: str
    session_id: str
    device_id: str
    token_hash: str                      # sha256 of the raw refresh token
    issued_at: datetime = Field(default_factory=now_utc)
    expires_at: datetime
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    replaced_by: str | None = None       # jti of the successor token
    reuse_detected_at: datetime | None = None
    status: Literal["active", "rotated", "revoked", "reused"] = "active"
