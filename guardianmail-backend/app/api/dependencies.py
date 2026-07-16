"""FastAPI dependencies for authenticated requests."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, Request

from app.core.exceptions import AuthError
from app.database.mongodb import get_db
from app.models.user import User
from app.repositories.sessions import SessionsRepository
from app.repositories.users import UsersRepository
from app.services.auth.jwt_service import jwt_service
from app.services.auth.session_service import session_service


@dataclass(slots=True)
class Principal:
    user: User
    user_id: str
    session_id: str
    device_id: str
    access_jti: str
    email: str


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("missing bearer token", code="missing_bearer")
    return authorization.split(" ", 1)[1]


async def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
) -> Principal:
    token = _bearer(authorization)
    payload = await jwt_service.verify_access(token)
    db = get_db()
    session = await SessionsRepository(db).find_by_id(payload["sid"])
    if not session or session.status != "active":
        raise AuthError("session not active", code="session_inactive")
    user = await UsersRepository(db).find_by_id(payload["sub"])
    if not user or user.status != "active":
        raise AuthError("user not active", code="user_inactive")
    # bind ctx for logging + touch session
    from app.core import context as ctx
    ctx.bind(user_id=user.id, device_id=session.device_id)
    await session_service.touch(session.id)
    return Principal(
        user=user, user_id=user.id, session_id=session.id,
        device_id=session.device_id, access_jti=payload.get("jti", ""),
        email=payload.get("email", user.email),
    )


CurrentUser = Depends(get_principal)
