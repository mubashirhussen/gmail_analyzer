"""Repository for OCR reports."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING

from app.models.ocr_report import OCRReport
from app.repositories.base import BaseRepository
from app.schemas.base import Page


class OCRReportRepository(BaseRepository[OCRReport]):
    collection_name = "ocr_reports"
    model = OCRReport

    async def find_by_hash(self, user_id: str, sha256: str) -> OCRReport | None:
        return await self.find_one({"user_id": user_id, "attachment.sha256": sha256})

    async def list_for_user(
        self, user_id: str, *, page: int = 1, page_size: int = 25
    ) -> Page[OCRReport]:
        return await self.paginate(
            {"user_id": user_id},
            page=page,
            page_size=page_size,
            sort=[("created_at", DESCENDING)],
        )

    async def set_status(self, report_id: str, status: str, extra: dict[str, Any] | None = None) -> None:
        update: dict[str, Any] = {"$set": {"status": status, **(extra or {})}}
        await self.update({"_id": report_id}, update)

    async def attach_threat_report(self, report_id: str, threat_report_id: str) -> None:
        await self.update(
            {"_id": report_id},
            {"$set": {"threat_report_id": threat_report_id}},
        )

    async def attach_ai_report(self, report_id: str, ai_report_id: str) -> None:
        await self.update(
            {"_id": report_id},
            {"$set": {"ai_report_id": ai_report_id}},
        )
