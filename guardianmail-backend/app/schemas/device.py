"""Device DTOs."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DeviceRegisterIn(BaseModel):
    fingerprint: str = Field(..., min_length=6, max_length=256)
    label: str | None = None


class DeviceRenameIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=64)


class DeviceOut(BaseModel):
    id: str
    label: str
    browser: str
    os: str
    device_type: str
    ip: str
    location: str
    trusted: bool
    risk: str
    first_seen_at: datetime
    last_seen_at: datetime
    is_current: bool = False
