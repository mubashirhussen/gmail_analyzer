"""Emails repository — metadata-only Gmail message store.

Kept intentionally domain-agnostic: repository methods only perform
persistence primitives. Anything that reads/writes external systems or
composes multi-collection state belongs in ``services.gmail.*``.
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

    async def upsert_by_gmail_id(self, doc: EmailDoc) -> tuple[str, bool]:
        """Upsert; returns ``(_id, inserted)``."""
        payload = doc.model_dump(by_alias=True)
        payload["updated_at"] = now_utc()
        # never overwrite creation timestamp or full-body retention flag on update
        payload.pop("created_at", None)
        set_on_insert = {
            "created_at": now_utc(),
            "ingested_at": now_utc(),
        }
        res = await self.col.find_one_and_update(
            {"gmail_id": doc.gmail_id, "user_id": doc.user_id},
            {"$set": payload, "$setOnInsert": set_on_insert},
            upsert=True,
            return_document=True,
        )
        # Motor doesn't reveal whether it was an insert; infer from version==0
        inserted = int(res.get("version", 0)) == 0
        return str(res["_id"]), inserted

    async def find_by_gmail_id(self, user_id: str, gmail_id: str) -> EmailDoc | None:
        return await self.find_one({"user_id": user_id, "gmail_id": gmail_id})

    async def list_for_user(
        self,
        user_id: str,
        *,
        since: datetime | None = None,
        label: str | None = None,
        sender_domain: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if since:
            f["received_at"] = {"$gte": since}
        if label:
            f["labels"] = label
        if sender_domain:
            f["sender_domain"] = sender_domain
        return await self.paginate(
            f, page=page, page_size=page_size, sort=[("received_at", DESCENDING)]
        )

    async def list_thread(self, user_id: str, thread_id: str) -> list[EmailDoc]:
        return await self.find_many(
            {"user_id": user_id, "thread_id": thread_id},
            limit=500,
            sort=[("received_at", 1)],
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

    async def apply_labels(self, user_id: str, gmail_id: str,
                           *, add: list[str], remove: list[str]) -> None:
        ops: dict[str, Any] = {}
        if add:
            ops["$addToSet"] = {"labels": {"$each": add}}
        if remove:
            ops["$pull"] = {"labels": {"$in": remove}}
        if ops:
            ops.setdefault("$set", {})
            ops["$set"]["updated_at"] = now_utc()
            await self.col.update_one(
                {"user_id": user_id, "gmail_id": gmail_id}, ops
            )

    async def delete_by_gmail_id(self, user_id: str, gmail_id: str) -> bool:
        res = await self.col.update_one(
            {"user_id": user_id, "gmail_id": gmail_id},
            {"$set": {"deleted_at": now_utc(), "updated_at": now_utc()}},
        )
        return res.modified_count == 1

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
