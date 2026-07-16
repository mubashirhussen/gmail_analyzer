"""Security audit trail (Module 11).

Persists structured audit records to Mongo (`platform_audit_log`) with a
capped-collection-friendly schema. Never blocks the request path — on
persistence failure the event is logged and dropped.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from app.database.mongodb import mongodb

log = structlog.get_logger(__name__)

COLLECTION = "platform_audit_log"


class AuditService:
    async def record(
        self,
        *,
        actor: str | None,
        action: str,
        resource: str | None = None,
        status: str = "ok",
        ip: str | None = None,
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        doc = {
            "ts": datetime.now(timezone.utc),
            "actor": actor,
            "action": action,
            "resource": resource,
            "status": status,
            "ip": ip,
            "request_id": request_id,
            "metadata": metadata or {},
        }
        try:
            await mongodb.db[COLLECTION].insert_one(doc)
        except Exception as exc:  # noqa: BLE001
            log.warning("audit_persist_failed", err=str(exc), action=action)


audit_service = AuditService()
