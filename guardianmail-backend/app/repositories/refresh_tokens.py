"""Refresh tokens repository — enforces rotation and reuse detection."""
from __future__ import annotations

from app.core.clock import now_utc
from app.models.refresh_token import RefreshToken
from app.repositories.base import BaseRepository


class RefreshTokensRepository(BaseRepository[RefreshToken]):
    collection_name = "refresh_tokens"
    model = RefreshToken

    async def create(self, token: RefreshToken) -> RefreshToken:
        await self.col.insert_one(token.model_dump(by_alias=True))
        return token

    async def get_by_jti(self, jti: str) -> RefreshToken | None:
        return await self.find_one({"jti": jti})

    async def mark_rotated(self, jti: str, successor_jti: str) -> int:
        res = await self.col.update_one(
            {"jti": jti, "status": "active"},
            {"$set": {"status": "rotated", "rotated_at": now_utc(),
                       "replaced_by": successor_jti}},
        )
        return res.modified_count

    async def mark_reused(self, jti: str) -> None:
        await self.col.update_one(
            {"jti": jti},
            {"$set": {"status": "reused", "reuse_detected_at": now_utc()}},
        )

    async def revoke_chain(self, session_id: str) -> int:
        res = await self.col.update_many(
            {"session_id": session_id, "status": {"$in": ["active", "rotated"]}},
            {"$set": {"status": "revoked", "revoked_at": now_utc()}},
        )
        return res.modified_count
