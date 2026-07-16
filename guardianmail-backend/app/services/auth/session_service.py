"""Session service — issues, refreshes, revokes sessions and enforces
refresh-token rotation with reuse detection.
"""
from __future__ import annotations

from datetime import timedelta

from app.core.clock import now_utc
from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.ids import uuid_str
from app.database.mongodb import get_db
from app.models.refresh_token import RefreshToken
from app.models.session import Session
from app.repositories.refresh_tokens import RefreshTokensRepository
from app.repositories.sessions import SessionsRepository
from app.repositories.users import UsersRepository
from app.services.auth.audit_service import audit_service
from app.services.auth.jwt_service import jwt_service


class SessionService:
    def _sessions(self) -> SessionsRepository:
        return SessionsRepository(get_db())

    def _refresh(self) -> RefreshTokensRepository:
        return RefreshTokensRepository(get_db())

    def _users(self) -> UsersRepository:
        return UsersRepository(get_db())

    async def create(self, *, user_id: str, device_id: str, email: str,
                     ip: str, user_agent: str, remember_me: bool) -> tuple[Session, str, str, int]:
        # concurrent-session limit
        active = await self._sessions().list_active(user_id)
        u = await self._users().find_by_id(user_id)
        limit = u.concurrent_session_limit if u else 10
        if len(active) >= limit:
            # revoke oldest
            oldest = sorted(active, key=lambda s: s.last_active_at)[0]
            await self._sessions().revoke(oldest.id, reason="concurrent_limit")

        ttl_days = settings.REFRESH_TOKEN_TTL_DAYS * (2 if remember_me else 1)
        jti = jwt_service.new_jti()
        session = Session(
            user_id=user_id, device_id=device_id, refresh_jti=jti,
            ip=ip, user_agent=user_agent, remember_me=remember_me,
            expires_at=now_utc() + timedelta(days=ttl_days),
        )
        await self._sessions().create(session)

        refresh_token, refresh_hash = jwt_service.issue_refresh(
            user_id=user_id, session_id=session.id, device_id=device_id, jti=jti,
        )
        await self._refresh().create(RefreshToken(
            jti=jti, user_id=user_id, session_id=session.id, device_id=device_id,
            token_hash=refresh_hash, expires_at=session.expires_at,
        ))
        access, expires_in = jwt_service.issue_access(
            user_id=user_id, session_id=session.id, device_id=device_id, email=email,
        )
        return session, access, refresh_token, expires_in

    async def refresh(self, refresh_token: str, *, ip: str = "") -> tuple[str, str, int, Session]:
        payload = jwt_service.decode(refresh_token, expected_type="refresh")
        jti = payload["jti"]
        record = await self._refresh().get_by_jti(jti)
        if not record:
            raise AuthError("unknown refresh token", code="unknown_refresh")

        # hash mismatch → tampered
        if record.token_hash != jwt_service.hash_token(refresh_token):
            raise AuthError("refresh token hash mismatch", code="tampered_refresh")

        # rotated/revoked/reused → treat as reuse attack, revoke entire chain
        if record.status != "active":
            await self._refresh().mark_reused(jti)
            await self._refresh().revoke_chain(record.session_id)
            await self._sessions().revoke(record.session_id, reason="refresh_reuse")
            await audit_service.security_event(
                "token_reuse", user_id=record.user_id, severity="critical",
                session_id=record.session_id, ip=ip,
                message="Refresh token reuse detected — session revoked",
            )
            raise AuthError("refresh token reuse detected", code="refresh_reuse")

        session = await self._sessions().find_by_id(record.session_id)
        if not session or session.status != "active":
            raise AuthError("session not active", code="session_inactive")

        # rotate
        new_jti = jwt_service.new_jti()
        new_refresh, new_hash = jwt_service.issue_refresh(
            user_id=record.user_id, session_id=session.id,
            device_id=session.device_id, jti=new_jti,
        )
        await self._refresh().create(RefreshToken(
            jti=new_jti, user_id=record.user_id, session_id=session.id,
            device_id=session.device_id, token_hash=new_hash,
            expires_at=session.expires_at,
        ))
        await self._refresh().mark_rotated(jti, new_jti)
        await self._sessions().rotate_refresh(session.id, new_jti)

        access, expires_in = jwt_service.issue_access(
            user_id=record.user_id, session_id=session.id,
            device_id=session.device_id, email=payload.get("email", ""),
        )
        await audit_service.audit("auth.refresh", user_id=record.user_id,
                                   session_id=session.id, device_id=session.device_id, ip=ip)
        return access, new_refresh, expires_in, session

    async def touch(self, session_id: str) -> None:
        await self._sessions().touch(session_id)

    async def revoke(self, session_id: str, *, user_id: str, reason: str = "logout",
                     access_jti: str | None = None) -> None:
        await self._sessions().revoke(session_id, reason=reason)
        await self._refresh().revoke_chain(session_id)
        if access_jti:
            await jwt_service.blacklist(access_jti)
        await audit_service.security_event("logout", user_id=user_id,
                                            session_id=session_id, message=reason)

    async def revoke_all(self, user_id: str, *, except_session: str | None = None) -> int:
        n = await self._sessions().revoke_all(user_id, except_session=except_session)
        await audit_service.security_event(
            "logout_all", user_id=user_id, severity="medium",
            message=f"Signed out {n} session(s)",
        )
        return n

    async def revoke_device_sessions(self, user_id: str, device_id: str) -> int:
        return await self._sessions().revoke_device(user_id, device_id)


session_service = SessionService()
