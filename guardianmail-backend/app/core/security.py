from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt

from app.core.config import settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(sub: str, **extra: Any) -> str:
    payload = {"sub": sub, "type": "access", "exp": _now() + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MIN), **extra}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALG)


def create_refresh_token(sub: str, jti: str) -> str:
    payload = {"sub": sub, "type": "refresh", "jti": jti, "exp": _now() + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)}
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
