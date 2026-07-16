"""Passcode service — optional 6-digit application lock.

Passcode is hashed with bcrypt (same context as passwords), stored on the
user document. Retries counted in Redis; hard lock after threshold.
"""
from __future__ import annotations

from datetime import timedelta

from app.core.clock import now_utc
from app.core.exceptions import AuthError, PermissionError as Forbidden
from app.core.security import hash_password, verify_password
from app.database.mongodb import get_db
from app.database.redis import get_redis
from app.repositories.users import UsersRepository
from app.services.auth.audit_service import audit_service
from app.services.auth.redis_keys import PASSCODE_FAIL

MAX_ATTEMPTS = 5
LOCK_SECONDS = 15 * 60


class PasscodeService:
    def _users(self) -> UsersRepository:
        return UsersRepository(get_db())

    async def status(self, user_id: str) -> dict:
        u = await self._users().find_by_id(user_id)
        fails = int(await get_redis().get(PASSCODE_FAIL.format(user_id=user_id)) or 0)
        locked = bool(u and u.passcode_locked_until and u.passcode_locked_until > now_utc())
        return {"enabled": bool(u and u.passcode_hash), "locked": locked,
                "remaining_attempts": max(0, MAX_ATTEMPTS - fails)}

    async def set(self, user_id: str, passcode: str) -> None:
        await self._users().set_passcode(user_id, hash_password(passcode))
        await get_redis().delete(PASSCODE_FAIL.format(user_id=user_id))
        await audit_service.security_event("passcode_set", user_id=user_id,
                                            message="Passcode enabled")

    async def change(self, user_id: str, current: str, new: str) -> None:
        u = await self._users().find_by_id(user_id)
        if not u or not u.passcode_hash or not verify_password(current, u.passcode_hash):
            await self._register_failure(user_id)
            raise AuthError("invalid current passcode", code="invalid_passcode")
        await self._users().set_passcode(user_id, hash_password(new))
        await audit_service.security_event("passcode_changed", user_id=user_id,
                                            message="Passcode changed")

    async def verify(self, user_id: str, passcode: str) -> None:
        u = await self._users().find_by_id(user_id)
        if not u or not u.passcode_hash:
            raise Forbidden("passcode not set", code="passcode_not_set")
        if u.passcode_locked_until and u.passcode_locked_until > now_utc():
            raise Forbidden("passcode locked", code="passcode_locked")
        if not verify_password(passcode, u.passcode_hash):
            await self._register_failure(user_id)
            raise AuthError("invalid passcode", code="invalid_passcode")
        await get_redis().delete(PASSCODE_FAIL.format(user_id=user_id))

    async def _register_failure(self, user_id: str) -> None:
        r = get_redis()
        key = PASSCODE_FAIL.format(user_id=user_id)
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, LOCK_SECONDS)
        if int(n) >= MAX_ATTEMPTS:
            until = now_utc() + timedelta(seconds=LOCK_SECONDS)
            await get_db().users.update_one(
                {"_id": user_id},
                {"$set": {"passcode_locked_until": until, "updated_at": now_utc()}},
            )
            await audit_service.security_event(
                "passcode_locked", user_id=user_id, severity="high",
                message="Passcode locked after too many failed attempts",
            )
        else:
            await audit_service.security_event(
                "passcode_failure", user_id=user_id, severity="medium",
                message=f"Invalid passcode (attempt {n}/{MAX_ATTEMPTS})",
            )


passcode_service = PasscodeService()
