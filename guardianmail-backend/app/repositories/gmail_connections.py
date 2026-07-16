"""Repository for GmailConnection documents.

Pure persistence — no OAuth I/O, no Gmail API calls; those belong to the
service layer.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.core.clock import now_utc
from app.models.gmail_connection import GmailConnection
from app.repositories.base import BaseRepository


class GmailConnectionsRepository(BaseRepository[GmailConnection]):
    collection_name = "gmail_connections"
    model = GmailConnection
    soft_delete = True

    async def get_active_for_user(self, user_id: str) -> GmailConnection | None:
        return await self.find_one({"user_id": user_id, "status": {"$ne": "revoked"}})

    async def find_by_email(self, user_id: str, email: str) -> GmailConnection | None:
        return await self.find_one({"user_id": user_id, "email": email.lower()})

    async def upsert(self, doc: GmailConnection) -> GmailConnection:
        existing = await self.find_by_email(doc.user_id, doc.email)
        if existing:
            patch: dict[str, Any] = {
                "refresh_token_enc": doc.refresh_token_enc,
                "scopes": doc.scopes,
                "status": "active",
                "last_error": None,
                "last_error_at": None,
                "connected_at": existing.connected_at or now_utc(),
                "disconnected_at": None,
                "reconnected_count": existing.reconnected_count + 1,
                "google_sub": doc.google_sub or existing.google_sub,
            }
            await self.update({"_id": existing.id}, {"$set": patch})
            return await self.get_by_id(existing.id)
        doc.connected_at = now_utc()
        await self.insert(doc)
        return doc

    async def mark_error(self, cid: str, *, code: str, message: str) -> None:
        await self.update(
            {"_id": cid},
            {"$set": {
                "status": "error" if code != "reauth" else "reauth_required",
                "last_error": f"{code}: {message}"[:512],
                "last_error_at": now_utc(),
            }},
        )

    async def mark_revoked(self, cid: str) -> None:
        await self.update(
            {"_id": cid},
            {"$set": {
                "status": "revoked",
                "disconnected_at": now_utc(),
            }},
        )

    async def update_cursor(
        self,
        cid: str,
        *,
        history_id: str | None,
        ingested: int,
        initial_completed: bool | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        patch: dict[str, Any] = {"status": "active", "last_success_at": now_utc()}
        if history_id:
            patch["history_id"] = history_id
        if initial_completed is not None:
            patch["initial_import_completed"] = initial_completed
        if started_at:
            patch["last_sync_started_at"] = started_at
        if finished_at:
            patch["last_sync_finished_at"] = finished_at
        inc = {"messages_synced_total": ingested} if ingested else None
        upd: dict[str, Any] = {"$set": patch}
        if inc:
            upd["$inc"] = inc
        await self.update({"_id": cid}, upd)

    async def all_active(self, limit: int = 5_000) -> list[GmailConnection]:
        return await self.find_many({"status": "active"}, limit=limit)
