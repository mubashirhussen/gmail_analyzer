"""Audit + security event service."""
from __future__ import annotations

from typing import Any

import structlog

from app.database.mongodb import get_db
from app.models.audit import AuditLog
from app.models.login_history import LoginHistory
from app.models.security_event import SecurityEvent, SecurityKind, SecuritySeverity
from app.repositories.audit_logs import (AuditLogsRepository,
                                         LoginHistoryRepository,
                                         SecurityEventsRepository)

log = structlog.get_logger("audit")


class AuditService:
    def _audit(self) -> AuditLogsRepository:
        return AuditLogsRepository(get_db())

    def _login(self) -> LoginHistoryRepository:
        return LoginHistoryRepository(get_db())

    def _events(self) -> SecurityEventsRepository:
        return SecurityEventsRepository(get_db())

    async def audit(self, action: str, *, user_id: str | None = None,
                    session_id: str | None = None, device_id: str | None = None,
                    ip: str = "", user_agent: str = "",
                    outcome: str = "success", meta: dict[str, Any] | None = None,
                    request_id: str = "") -> None:
        entry = AuditLog(action=action, user_id=user_id, session_id=session_id,
                         device_id=device_id, ip=ip, user_agent=user_agent,
                         outcome=outcome, meta=meta or {}, request_id=request_id)
        await self._audit().record(entry)
        log.info("audit", action=action, user_id=user_id, outcome=outcome)

    async def login_history(self, **fields) -> None:
        await self._login().record(LoginHistory(**fields))

    async def security_event(self, kind: SecurityKind, *,
                             user_id: str | None = None,
                             severity: SecuritySeverity = "info",
                             message: str = "", ip: str = "",
                             device_id: str | None = None,
                             session_id: str | None = None,
                             meta: dict[str, Any] | None = None) -> None:
        ev = SecurityEvent(kind=kind, user_id=user_id, severity=severity,
                            message=message, ip=ip, device_id=device_id,
                            session_id=session_id, meta=meta or {})
        await self._events().record(ev)
        log.info("security_event", kind=kind, severity=severity, user_id=user_id)


audit_service = AuditService()
