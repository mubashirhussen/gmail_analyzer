"""JWT service — signs, verifies, rotates, and blacklists tokens.

Access tokens are short-lived, opaque to the client, and carry
`sid` (session id) + `did` (device id) so downstream services can
authorise without extra DB reads. Refresh tokens are one-time-use;
rotation and reuse detection live in `SessionService`.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from jose import JWTError, jwt

from app.core.clock import now_utc
from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.ids import uuid_str
from app.database.redis import get_redis
from app.services.auth.redis_keys import (BLACKLIST, BLACKLIST_TTL_S)


class JWTService:
    def __init__(self) -> None:
        self.alg = settings.JWT_ALG
        self.key = settings.SECRET_KEY
        self.access_ttl = timedelta(minutes=settings.ACCESS_TOKEN_TTL_MIN)
        self.refresh_ttl = timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)

    # ---- issue ----------------------------------------------------------
    def issue_access(self, *, user_id: str, session_id: str, device_id: str,
                     email: str) -> tuple[str, int]:
        now = now_utc()
        payload = {
            "sub": user_id, "type": "access",
            "sid": session_id, "did": device_id, "email": email,
            "jti": uuid_str(),
            "iat": int(now.timestamp()),
            "exp": now + self.access_ttl,
        }
        return jwt.encode(payload, self.key, algorithm=self.alg), int(self.access_ttl.total_seconds())

    def issue_refresh(self, *, user_id: str, session_id: str, device_id: str,
                      jti: str) -> tuple[str, str]:
        now = now_utc()
        payload = {
            "sub": user_id, "type": "refresh",
            "sid": session_id, "did": device_id, "jti": jti,
            "iat": int(now.timestamp()),
            "exp": now + self.refresh_ttl,
        }
        token = jwt.encode(payload, self.key, algorithm=self.alg)
        return token, hashlib.sha256(token.encode()).hexdigest()

    # ---- verify ---------------------------------------------------------
    def decode(self, token: str, *, expected_type: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(token, self.key, algorithms=[self.alg])
        except JWTError as e:
            raise AuthError("invalid token", code="invalid_token") from e
        if payload.get("type") != expected_type:
            raise AuthError("wrong token type", code="wrong_token_type")
        return payload

    async def verify_access(self, token: str) -> dict[str, Any]:
        payload = self.decode(token, expected_type="access")
        jti = payload.get("jti", "")
        if jti and await get_redis().exists(BLACKLIST.format(jti=jti)):
            raise AuthError("token revoked", code="token_revoked")
        return payload

    async def blacklist(self, jti: str, *, ttl_s: int = BLACKLIST_TTL_S) -> None:
        await get_redis().set(BLACKLIST.format(jti=jti), "1", ex=ttl_s)

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def new_jti() -> str:
        return uuid_str()


jwt_service = JWTService()
