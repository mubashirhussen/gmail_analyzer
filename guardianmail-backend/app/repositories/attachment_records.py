"""Repository for deduplicated attachment records (identity, not payload)."""
from __future__ import annotations

from app.core.clock import now_utc
from app.models.attachment_record import AttachmentRecord
from app.repositories.base import BaseRepository


class AttachmentRecordRepository(BaseRepository[AttachmentRecord]):
    collection_name = "attachment_records"
    model = AttachmentRecord

    async def upsert(self, record: AttachmentRecord) -> AttachmentRecord:
        existing = await self.find_one(
            {"user_id": record.user_id, "sha256": record.sha256}
        )
        if existing:
            await self.update(
                {"_id": existing.id},
                {
                    "$set": {
                        "last_seen_at": now_utc(),
                        "risk_flags": list(sorted(set(existing.risk_flags) | set(record.risk_flags))),
                        "ocr_report_id": record.ocr_report_id or existing.ocr_report_id,
                    },
                    "$inc": {"seen_count": 1},
                },
            )
            return await self.get_by_id(existing.id)
        await self.insert(record)
        return record

    async def find_by_hash(self, user_id: str, sha256: str) -> AttachmentRecord | None:
        return await self.find_one({"user_id": user_id, "sha256": sha256})
