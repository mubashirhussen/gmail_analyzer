"""Session DTOs."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class SessionOut(BaseModel):
    id: str
    device_id: str
    ip: str
    user_agent: str
    issued_at: datetime
    last_active_at: datetime
    expires_at: datetime
    status: str
    is_current: bool = False
