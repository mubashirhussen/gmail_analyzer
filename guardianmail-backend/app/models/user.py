from datetime import datetime
from pydantic import BaseModel, EmailStr


class UserDoc(BaseModel):
    email: EmailStr
    name: str | None = None
    picture: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
    gmail_refresh_encrypted: str | None = None
