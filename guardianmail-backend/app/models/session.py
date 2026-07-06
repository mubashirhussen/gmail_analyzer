from datetime import datetime
from pydantic import BaseModel


class SessionDoc(BaseModel):
    user_id: str
    device_id: str | None = None
    session_token: str
    refresh_jti: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    created_at: datetime
    last_active: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
