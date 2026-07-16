"""Emails repository — metadata-only Gmail message store.

Domain queries kept here (nothing business-logic):
* filter by user + received range + label
* fetch messages awaiting scan
* upsert on gmail_id (idempotent sync)
* aggregation of sender-domain counts (feeds analytics)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.email import EmailDoc
from app.repositories.base import BaseRepository


class EmailRepository(BaseRepository[EmailDoc]):
    collection_name = "emails"
    model = EmailDoc
    soft_delete = True

    async def upsert_by_gmail_id(self, doc: EmailDoc) -> str:
        payload = doc.model_dump(by_alias=True)
        payload["updated_at"] = now_utc()
        res = await self.col.find_one_and_update(
            {"gmail_id": doc.gmail_id, "user_id": doc.user_id},
            {"$set": payload, "$setOnInsert": {"created_at": now_utc()}},
            upsert=True,
            return_document=True,
        )
        return str(res["_id"])

    async def list_for_user(
        self,
        user_id: str,
        *,
        since: datetime | None = None,
        label: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if since:
            f["received_at"] = {"$gte": since}
        if label:
            f["labels"] = label
        return await self.paginate(
            f, page=page, page_size=page_size, sort=[("received_at", DESCENDING)]
        )

    async def pending_scan(self, user_id: str, limit: int = 100) -> list[EmailDoc]:
        return await self.find_many(
            {"user_id": user_id, "analysis_status": "pending"},
            limit=limit,
            sort=[("received_at", DESCENDING)],
        )

    async def mark_analysis(self, email_id: str, status: str, threat_id: str | None = None) -> None:
        upd: dict[str, Any] = {"analysis_status": status}
        if threat_id:
            upd["threat_id"] = threat_id
        await self.update({"_id": email_id}, {"$set": upd})

    async def top_sender_domains(
        self, user_id: str, *, days: int = 30, limit: int = 20
    ) -> list[dict]:
        from datetime import timedelta

        since = now_utc() - timedelta(days=days)
        pipeline = [
            {"$match": {"user_id": user_id, "received_at": {"$gte": since}, "deleted_at": None}},
            {"$group": {"_id": "$sender_domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
        ]
        return await self.aggregate(pipeline)
