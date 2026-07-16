"""Report record repository."""
from __future__ import annotations

from datetime import datetime

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.report_record import ReportRecord
from app.repositories.base import BaseRepository


class ReportRecordsRepository(BaseRepository[ReportRecord]):
    collection_name = "report_records"
    model = ReportRecord
    soft_delete = False

    async def list_for_user(
        self, user_id: str, *, kind: str | None = None, limit: int = 50
    ) -> list[ReportRecord]:
        q: dict = {"user_id": user_id}
        if kind:
            q["kind"] = kind
        return await self.find_many(q, sort=[("requested_at", DESCENDING)], limit=limit)

    async def set_status(
        self,
        report_id: str,
        status: str,
        *,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        upd: dict = {"status": status, "updated_at": now_utc()}
        if error is not None:
            upd["error"] = error
        if extra:
            upd.update(extra)
        await self.col.update_one({"_id": report_id}, {"$set": upd})

    async def mark_downloaded(self, report_id: str) -> None:
        await self.col.update_one(
            {"_id": report_id},
            {"$set": {"last_downloaded_at": now_utc()}, "$inc": {"download_count": 1}},
        )

    async def by_download_token(self, token: str) -> ReportRecord | None:
        return await self.find_one({"download_token": token})
