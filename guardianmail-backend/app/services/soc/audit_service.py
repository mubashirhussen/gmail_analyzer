"""Audit logging service — tamper-evident append-only trail."""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.soc import AuditLogEntry
from app.repositories.soc import AuditRepository

_log = get_logger(__name__)


class AuditService:
    async def log(
        self,
        *,
        actor: str,
        action: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        user_id: str | None = None,
        meta: dict[str, Any] | None = None,
        ip: str | None = None,
        request_id: str | None = None,
    ) -> str:
        db = get_db()
        entry = AuditLogEntry(
            actor=actor, action=action, entity_type=entity_type,
            entity_id=entity_id, user_id=user_id, meta=meta or {},
            ip=ip, request_id=request_id,
        )
        try:
            inserted = await AuditRepository(db).insert(entry)
        except Exception as exc:  # pragma: no cover - never break caller
            _log.warning("audit_log_failed", action=action, err=str(exc))
            return ""
        return str(inserted)


audit_service = AuditService()
