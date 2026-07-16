"""Evidence pack repository."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING

from app.core.clock import now_utc
from app.models.evidence_pack import EvidencePack, PackStatus
from app.repositories.base import BaseRepository


class EvidencePackRepository(BaseRepository[EvidencePack]):
    collection_name = "evidence_packs"
    model = EvidencePack
    soft_delete = True

    async def list_for_user(self, user_id: str, *, page: int = 1, page_size: int = 25):
        return await self.paginate(
            {"user_id": user_id},
            page=page,
            page_size=page_size,
            sort=[("generated_at", DESCENDING)],
        )

    async def for_report(self, threat_report_id: str) -> EvidencePack | None:
        return await self.find_one(
            {"threat_report_id": threat_report_id}, sort=[("created_at", DESCENDING)]
        )

    async def mark_ready(self, pack_id: str, *, manifest_sha256: str, signature: str) -> None:
        await self.update(
            {"_id": pack_id},
            {
                "$set": {
                    "status": "ready",
                    "manifest_sha256": manifest_sha256,
                    "signature": signature,
                    "generated_at": now_utc(),
                }
            },
        )

    async def record_download(self, pack_id: str) -> None:
        await self.update(
            {"_id": pack_id},
            {"$set": {"downloaded_at": now_utc(), "status": "downloaded"}, "$inc": {"download_count": 1}},
        )
