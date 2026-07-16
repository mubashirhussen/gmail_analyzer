"""Google OAuth 2.0 adapter — authorization-code flow with CSRF state.

State is minted server-side, stored in Redis with a short TTL, and includes
a return-url + remember-me flag so the callback can complete the intent.
Token exchange + userinfo happen through the shared pooled httpx client.
"""
from __future__ import annotations

import json
from urllib.parse import urlencode

from app.core.config import settings
from app.core.exceptions import AuthError, ExternalServiceError
from app.core.http import get_client
from app.core.ids import opaque_token
from app.database.redis import get_redis
from app.services.auth.redis_keys import OAUTH_STATE, OAUTH_STATE_TTL_S


AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL     = "https://oauth2.googleapis.com/token"
USERINFO_URL  = "https://www.googleapis.com/oauth2/v3/userinfo"

DEFAULT_SCOPES = ("openid", "email", "profile",
                  "https://www.googleapis.com/auth/gmail.readonly")


class OAuthService:
    async def build_authorize_url(self, *, redirect_uri: str | None = None,
                                  remember_me: bool = False) -> tuple[str, str]:
        state = opaque_token(32)
        payload = {"redirect_uri": redirect_uri or settings.GOOGLE_OAUTH_REDIRECT,
                   "remember_me": remember_me}
        await get_redis().set(OAUTH_STATE.format(state=state),
                              json.dumps(payload), ex=OAUTH_STATE_TTL_S)
        params = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "redirect_uri": payload["redirect_uri"],
            "response_type": "code",
            "scope": " ".join(DEFAULT_SCOPES),
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "select_account",
            "state": state,
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}", state

    async def consume_state(self, state: str) -> dict:
        key = OAUTH_STATE.format(state=state)
        raw = await get_redis().get(key)
        if not raw:
            raise AuthError("invalid or expired oauth state", code="invalid_state")
        await get_redis().delete(key)
        return json.loads(raw)

    async def exchange_code(self, code: str, redirect_uri: str) -> dict:
        r = await get_client().post(TOKEN_URL, data={
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })
        if r.status_code != 200:
            raise ExternalServiceError(f"google token exchange failed: {r.text}",
                                       code="oauth_exchange_failed")
        return r.json()

    async def fetch_userinfo(self, access_token: str) -> dict:
        r = await get_client().get(USERINFO_URL,
                                   headers={"Authorization": f"Bearer {access_token}"})
        if r.status_code != 200:
            raise ExternalServiceError("google userinfo failed",
                                       code="oauth_userinfo_failed")
        return r.json()


oauth_service = OAuthService()
