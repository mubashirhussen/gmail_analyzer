from datetime import datetime
from pydantic import BaseModel


class DeviceDoc(BaseModel):
    user_id: str
    fingerprint: str
    label: str | None = None
    os: str | None = None
    browser: str | None = None
    ip: str | None = None
    city: str | None = None
    country: str | None = None
    trusted: bool = True
    status: str = "active"  # active | revoked
    first_seen: datetime
    last_seen: datetime
