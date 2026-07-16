"""Security service — lockout / brute-force protection."""
from __future__ import annotations

from datetime import timedelta

from app.core.clock import now_utc
from app.core.exceptions import RateLimitError
from app.database.mongodb import get_db
from app.database.redis import get_redis
from app.repositories.users import UsersRepository
from app.services.auth.audit_service import audit_service
from app.services.auth.redis_keys import (LOCKOUT, LOCKOUT_THRESHOLD, LOCKOUT_TTL_S)


class SecurityService:
    def _users(self) -> UsersRepository:
        return UsersRepository(get_db())

    async def check_not_locked(self, email: str) -> None:
        n = int(await get_redis().get(LOCKOUT.format(email=email.lower())) or 0)
        if n >= LOCKOUT_THRESHOLD:
            raise RateLimitError("too many failed attempts, try later",
                                 code="account_lockout")

    async def register_failure(self, email: str, ip: str, reason: str) -> None:
        r = get_redis()
        key = LOCKOUT.format(email=email.lower())
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, LOCKOUT_TTL_S)
        await audit_service.security_event(
            "login_failure", severity="medium",
            message=reason, ip=ip, meta={"email": email, "count": int(n)},
        )
        if int(n) >= LOCKOUT_THRESHOLD:
            u = await self._users().get_by_email(email)
            if u:
                await self._users().lock(u.id, now_utc() + timedelta(seconds=LOCKOUT_TTL_S))
                await audit_service.security_event(
                    "account_locked", user_id=u.id, severity="high", ip=ip,
                    message="Account locked after repeated failures",
                )

    async def clear_failures(self, email: str) -> None:
        await get_redis().delete(LOCKOUT.format(email=email.lower()))


security_service = SecurityService()
