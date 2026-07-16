"""Sessions repository."""
from __future__ import annotations

from datetime import datetime

from app.core.clock import now_utc
from app.models.session import Session
from app.repositories.base import BaseRepository


class SessionsRepository(BaseRepository[Session]):
    collection_name = "sessions"
    model = Session

    async def create(self, session: Session) -> Session:
        await self.col.insert_one(session.model_dump(by_alias=True))
        return session

    async def list_active(self, user_id: str) -> list[Session]:
        return await self.find_many(
            {"user_id": user_id, "status": "active"},
            sort=[("last_active_at", -1)],
            limit=100,
        )

    async def touch(self, session_id: str) -> None:
        await self.col.update_one(
            {"_id": session_id, "status": "active"},
            {"$set": {"last_active_at": now_utc()}},
        )

    async def rotate_refresh(self, session_id: str, new_jti: str) -> None:
        await self.col.update_one(
            {"_id": session_id},
            {"$set": {"refresh_jti": new_jti, "last_active_at": now_utc()}},
        )

    async def revoke(self, session_id: str, reason: str = "logout") -> int:
        res = await self.col.update_one(
            {"_id": session_id, "status": "active"},
            {"$set": {"status": "revoked", "revoked_at": now_utc(),
                       "revoke_reason": reason}},
        )
        return res.modified_count

    async def revoke_all(self, user_id: str, *, except_session: str | None = None,
                         reason: str = "logout_all") -> int:
        q: dict = {"user_id": user_id, "status": "active"}
        if except_session:
            q["_id"] = {"$ne": except_session}
        res = await self.col.update_many(
            q,
            {"$set": {"status": "revoked", "revoked_at": now_utc(),
                       "revoke_reason": reason}},
        )
        return res.modified_count

    async def revoke_device(self, user_id: str, device_id: str) -> int:
        res = await self.col.update_many(
            {"user_id": user_id, "device_id": device_id, "status": "active"},
            {"$set": {"status": "revoked", "revoked_at": now_utc(),
                       "revoke_reason": "device_removed"}},
        )
        return res.modified_count

    async def expire_stale(self, idle_seconds: int) -> int:
        cutoff = now_utc().timestamp() - idle_seconds
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)
        res = await self.col.update_many(
            {"status": "active", "last_active_at": {"$lt": dt}},
            {"$set": {"status": "expired", "revoked_at": now_utc(),
                       "revoke_reason": "idle_timeout"}},
        )
        return res.modified_count
