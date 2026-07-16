"""JWT, password hashing, and symmetric encryption helpers.

All token creation/verification funnels through this module so key
rotation and algorithm changes happen in one place.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import Header, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.clock import now_utc
from app.core.config import settings


# ---- password hashing ----------------------------------------------------
_pwd = CryptContext(schemes=[settings.PASSWORD_HASH_SCHEME], deprecated="auto")


def hash_password(raw: str) -> str:
    return _pwd.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return _pwd.verify(raw, hashed)
    except ValueError:
        return False


# ---- jwt -----------------------------------------------------------------
def create_access_token(sub: str, **extra: Any) -> str:
    payload = {
        "sub": sub,
        "type": "access",
        "iat": int(now_utc().timestamp()),
        "exp": now_utc() + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MIN),
        **extra,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALG)


def create_refresh_token(sub: str, jti: str) -> str:
    payload = {
        "sub": sub,
        "type": "refresh",
        "jti": jti,
        "iat": int(now_utc().timestamp()),
        "exp": now_utc() + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALG])
    except JWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from e


def require_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer")
    payload = decode_token(authorization.split(" ", 1)[1])
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
    return payload
