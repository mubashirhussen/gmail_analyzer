"""Background job repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING

from app.core.clock import now_utc
from app.models.background_job import BackgroundJob, JobStatus
from app.repositories.base import BaseRepository


class BackgroundJobRepository(BaseRepository[BackgroundJob]):
    collection_name = "background_jobs"
    model = BackgroundJob
    soft_delete = False

    async def list_for_user(
        self,
        user_id: str,
        *,
        status: JobStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if status:
            f["status"] = status
        return await self.paginate(
            f, page=page, page_size=page_size, sort=[("created_at", DESCENDING)]
        )

    async def due(self, before: datetime | None = None, limit: int = 100) -> list[BackgroundJob]:
        cutoff = before or now_utc()
        return await self.find_many(
            {"status": "pending", "scheduled_for": {"$lte": cutoff}},
            limit=limit,
            sort=[("scheduled_for", ASCENDING)],
        )

    async def transition(
        self,
        job_id: str,
        status: JobStatus,
        *,
        result: dict | None = None,
        error: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        upd: dict[str, Any] = {"status": status}
        if status == "running":
            upd["started_at"] = now_utc()
        elif status in ("success", "failed", "cancelled"):
            upd["finished_at"] = now_utc()
        if result is not None:
            upd["result"] = result
        if error is not None:
            upd["error"] = error
        if duration_ms is not None:
            upd["duration_ms"] = duration_ms
        await self.update({"_id": job_id}, {"$set": upd})

    async def bump_retry(self, job_id: str) -> None:
        await self.update({"_id": job_id}, {"$inc": {"retry_count": 1}})
