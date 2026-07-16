"""Auth request/response DTOs."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# ---- OAuth --------------------------------------------------------------
class OAuthLoginStart(BaseModel):
    redirect_uri: str | None = None
    remember_me: bool = False


class OAuthLoginStartResponse(BaseModel):
    authorize_url: str
    state: str


class OAuthCallbackIn(BaseModel):
    code: str
    state: str
    redirect_uri: str | None = None


# ---- tokens -------------------------------------------------------------
class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int                      # seconds until access token expiry


class AccessTokenOnly(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class RefreshIn(BaseModel):
    refresh_token: str


# ---- profile ------------------------------------------------------------
class UserProfile(BaseModel):
    id: str
    email: EmailStr
    email_verified: bool
    name: str | None = None
    picture: str | None = None
    status: str
    last_login_at: datetime | None = None


class LoginResponse(BaseModel):
    user: UserProfile
    session_id: str
    device_id: str
    tokens: TokenPair
