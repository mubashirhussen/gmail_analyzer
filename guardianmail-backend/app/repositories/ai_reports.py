"""AI report repository."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING

from app.models.ai_report import AIReport
from app.repositories.base import BaseRepository


class AIReportRepository(BaseRepository[AIReport]):
    collection_name = "ai_reports"
    model = AIReport
    soft_delete = True

    async def latest_for_threat(self, threat_report_id: str) -> AIReport | None:
        return await self.find_one(
            {"threat_report_id": threat_report_id},
            sort=[("created_at", DESCENDING)],
        )

    async def latest_for_email(self, email_id: str) -> AIReport | None:
        return await self.find_one(
            {"email_id": email_id},
            sort=[("created_at", DESCENDING)],
        )

    async def list_for_user(
        self, user_id: str, *, page: int = 1, page_size: int = 25,
        verdict: str | None = None,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if verdict:
            f["verdict"] = verdict
        return await self.paginate(f, page=page, page_size=page_size,
                                   sort=[("created_at", DESCENDING)])
