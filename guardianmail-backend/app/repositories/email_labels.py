"""EmailLabel repository."""
from __future__ import annotations

from app.core.clock import now_utc
from app.models.email_label import EmailLabel
from app.repositories.base import BaseRepository


class EmailLabelsRepository(BaseRepository[EmailLabel]):
    collection_name = "email_labels"
    model = EmailLabel
    soft_delete = False

    async def upsert(self, doc: EmailLabel) -> None:
        payload = doc.model_dump(by_alias=True)
        payload["updated_at"] = now_utc()
        await self.col.update_one(
            {"user_id": doc.user_id, "label_id": doc.label_id},
            {"$set": payload, "$setOnInsert": {"created_at": now_utc()}},
            upsert=True,
        )

    async def list_for_user(self, user_id: str) -> list[EmailLabel]:
        return await self.find_many({"user_id": user_id}, limit=500,
                                    sort=[("type", 1), ("name", 1)])

    async def replace_all(self, user_id: str, labels: list[EmailLabel]) -> int:
        """Full-refresh of the label set for a user."""
        seen = {l.label_id for l in labels}
        for l in labels:
            await self.upsert(l)
        # remove deleted labels
        res = await self.col.delete_many(
            {"user_id": user_id, "label_id": {"$nin": list(seen)}}
        )
        return res.deleted_count
