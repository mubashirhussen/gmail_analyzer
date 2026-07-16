"""SyncLog repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.sync_log import SyncLog
from app.repositories.base import BaseRepository


class SyncLogsRepository(BaseRepository[SyncLog]):
    collection_name = "sync_logs"
    model = SyncLog
    soft_delete = False

    async def start(self, log: SyncLog) -> str:
        await self.insert(log)
        return log.id

    async def finish(
        self,
        log_id: str,
        *,
        status: str,
        counters: dict[str, int] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        ended_history_id: str | None = None,
    ) -> None:
        started = await self.find_by_id(log_id)
        finished_at = now_utc()
        duration_ms = None
        if started and started.started_at:
            duration_ms = int((finished_at - started.started_at).total_seconds() * 1000)
        patch: dict[str, Any] = {
            "status": status,
            "finished_at": finished_at,
            "duration_ms": duration_ms,
        }
        if ended_history_id:
            patch["ended_history_id"] = ended_history_id
        if error_code:
            patch["error_code"] = error_code
        if error_message:
            patch["error_message"] = error_message[:1024]
        inc = counters or {}
        upd: dict[str, Any] = {"$set": patch}
        if inc:
            upd["$inc"] = inc
        await self.update({"_id": log_id}, upd, touch=False)

    async def history(self, user_id: str, *, page: int = 1, page_size: int = 25):
        return await self.paginate(
            {"user_id": user_id},
            page=page,
            page_size=page_size,
            sort=[("started_at", DESCENDING)],
        )

    async def last_success(self, user_id: str) -> SyncLog | None:
        return await self.find_one(
            {"user_id": user_id, "status": "success"},
            sort=[("finished_at", DESCENDING)],
        )
