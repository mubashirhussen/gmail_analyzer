"""Audit / login-history / security-event repositories."""
from __future__ import annotations

from app.models.audit import AuditLog
from app.models.login_history import LoginHistory
from app.models.security_event import SecurityEvent
from app.repositories.base import BaseRepository


class AuditLogsRepository(BaseRepository[AuditLog]):
    collection_name = "audit_logs"
    model = AuditLog

    async def record(self, entry: AuditLog) -> None:
        await self.col.insert_one(entry.model_dump(by_alias=True))


class LoginHistoryRepository(BaseRepository[LoginHistory]):
    collection_name = "login_history"
    model = LoginHistory

    async def record(self, entry: LoginHistory) -> None:
        await self.col.insert_one(entry.model_dump(by_alias=True))

    async def recent(self, user_id: str, limit: int = 50) -> list[LoginHistory]:
        return await self.find_many({"user_id": user_id},
                                    sort=[("at", -1)], limit=limit)


class SecurityEventsRepository(BaseRepository[SecurityEvent]):
    collection_name = "security_events"
    model = SecurityEvent

    async def record(self, event: SecurityEvent) -> None:
        await self.col.insert_one(event.model_dump(by_alias=True))

    async def recent(self, user_id: str, limit: int = 50) -> list[SecurityEvent]:
        return await self.find_many({"user_id": user_id},
                                    sort=[("at", -1)], limit=limit)
