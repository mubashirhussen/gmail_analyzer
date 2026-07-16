"""Users repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.clock import now_utc
from app.models.user import User
from app.repositories.base import BaseRepository


class UsersRepository(BaseRepository[User]):
    collection_name = "users"
    model = User

    async def get_by_email(self, email: str) -> User | None:
        return await self.find_one({"email": email.lower()})

    async def get_by_google_sub(self, sub: str) -> User | None:
        return await self.find_one({"google_sub": sub})

    async def upsert_from_google(self, info: dict[str, Any]) -> User:
        email = (info["email"] or "").lower()
        now = now_utc()
        await self.col.update_one(
            {"email": email},
            {
                "$setOnInsert": {"_id": User().id, "created_at": now, "status": "active"},
                "$set": {
                    "email": email,
                    "email_verified": bool(info.get("email_verified", True)),
                    "name": info.get("name"),
                    "picture": info.get("picture"),
                    "locale": info.get("locale"),
                    "google_sub": info.get("sub"),
                    "updated_at": now,
                },
            },
            upsert=True,
        )
        u = await self.get_by_email(email)
        assert u is not None
        return u

    async def touch_login(self, user_id: str, ip: str) -> None:
        await self.col.update_one(
            {"_id": user_id},
            {"$set": {"last_login_at": now_utc(), "last_login_ip": ip,
                       "failed_login_count": 0, "updated_at": now_utc()}},
        )

    async def register_failed_login(self, email: str) -> int:
        res = await self.col.find_one_and_update(
            {"email": email.lower()},
            {"$inc": {"failed_login_count": 1}, "$set": {"updated_at": now_utc()}},
            return_document=True,
        )
        return int(res.get("failed_login_count", 0)) if res else 0

    async def lock(self, user_id: str, until: datetime) -> None:
        await self.col.update_one(
            {"_id": user_id},
            {"$set": {"status": "locked", "locked_until": until, "updated_at": now_utc()}},
        )

    async def unlock(self, user_id: str) -> None:
        await self.col.update_one(
            {"_id": user_id},
            {"$set": {"status": "active", "locked_until": None,
                       "failed_login_count": 0, "updated_at": now_utc()}},
        )

    async def set_passcode(self, user_id: str, hashed: str | None) -> None:
        await self.col.update_one(
            {"_id": user_id},
            {"$set": {
                "passcode_hash": hashed,
                "passcode_updated_at": now_utc(),
                "passcode_failed_count": 0,
                "passcode_locked_until": None,
                "updated_at": now_utc(),
            }},
        )
