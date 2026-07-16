"""AI decision history repository (append-only)."""
from __future__ import annotations

from typing import Any

from pymongo import DESCENDING

from app.models.ai_decision import AIDecisionHistory
from app.repositories.base import BaseRepository


class AIDecisionHistoryRepository(BaseRepository[AIDecisionHistory]):
    collection_name = "ai_decision_history"
    model = AIDecisionHistory
    soft_delete = False

    async def list_for_user(self, user_id: str, *, page: int = 1, page_size: int = 25):
        return await self.paginate(
            {"user_id": user_id}, page=page, page_size=page_size,
            sort=[("created_at", DESCENDING)],
        )

    async def by_prompt_version(self, prompt_version: str, limit: int = 100) -> list[dict]:
        f: dict[str, Any] = {"prompt_version": prompt_version}
        return await self.find_many(f, limit=limit, sort=[("created_at", DESCENDING)])
