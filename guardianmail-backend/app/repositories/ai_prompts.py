"""AI prompt template repository."""
from __future__ import annotations

from pymongo import DESCENDING

from app.models.ai_prompt import AIPromptTemplate
from app.repositories.base import BaseRepository


class AIPromptRepository(BaseRepository[AIPromptTemplate]):
    collection_name = "ai_prompts"
    model = AIPromptTemplate
    soft_delete = False

    async def active(self, name: str) -> AIPromptTemplate | None:
        return await self.find_one(
            {"name": name, "active": True},
            sort=[("created_at", DESCENDING)],
        )

    async def by_checksum(self, checksum: str) -> AIPromptTemplate | None:
        return await self.find_one({"checksum": checksum})
