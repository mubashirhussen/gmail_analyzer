"""Complaint repository."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING

from app.core.clock import now_utc
from app.models.complaint import Complaint, ComplaintStatus
from app.repositories.base import BaseRepository


class ComplaintRepository(BaseRepository[Complaint]):
    collection_name = "complaints"
    model = Complaint
    soft_delete = True

    async def list_for_user(
        self,
        user_id: str,
        *,
        status: ComplaintStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if status:
            f["status"] = status
        return await self.paginate(f, page=page, page_size=page_size)

    async def due_for_dispatch(self, before: datetime | None = None, limit: int = 50) -> list[Complaint]:
        cutoff = before or now_utc()
        return await self.find_many(
            {"status": "scheduled", "scheduled_for": {"$lte": cutoff}},
            limit=limit,
            sort=[("scheduled_for", ASCENDING)],
        )

    async def set_status(
        self,
        complaint_id: str,
        status: ComplaintStatus,
        *,
        external_reference: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        upd: dict[str, Any] = {"status": status}
        if status == "sent":
            upd["submitted_at"] = now_utc()
        elif status == "acknowledged":
            upd["acknowledged_at"] = now_utc()
        if external_reference:
            upd["external_reference"] = external_reference
        if failure_reason:
            upd["failure_reason"] = failure_reason
        await self.update({"_id": complaint_id}, {"$set": upd})

    async def status_counts(self, user_id: str) -> list[dict]:
        pipeline = [
            {"$match": {"user_id": user_id, "deleted_at": None}},
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        ]
        return await self.aggregate(pipeline)
