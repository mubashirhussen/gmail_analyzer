from datetime import datetime
from pydantic import BaseModel


class DeviceOut(BaseModel):
    id: str
    label: str | None = None
    os: str | None = None
    browser: str | None = None
    trusted: bool
    status: str
    last_seen: datetime


class DeviceRegisterIn(BaseModel):
    fingerprint: str
    label: str
    os: str
    browser: str
    session_token: str
