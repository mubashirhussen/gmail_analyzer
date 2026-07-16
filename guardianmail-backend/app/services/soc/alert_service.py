"""Alert service — raise, list, and acknowledge SOC alerts."""
from __future__ import annotations

from typing import Any

from app.core.clock import now_utc
from app.database.mongodb import get_db
from app.models.soc import Alert
from app.repositories.soc import AlertRepository
from app.services.soc.audit_service import audit_service


_ALLOWED_KINDS = {
    "critical_threat", "ai_failure", "redis_failure", "mongo_failure",
    "queue_growth", "high_api_latency", "provider_failure",
    "multiple_phishing_emails", "repeated_sender", "incident_escalated",
}


class AlertService:
    async def raise_alert(
        self,
        *,
        kind: str,
        title: str,
        severity: str = "high",
        message: str = "",
        user_id: str | None = None,
        incident_id: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> str:
        if kind not in _ALLOWED_KINDS:
            kind = "critical_threat"
        db = get_db()
        alert = Alert(
            kind=kind, severity=severity, title=title, message=message,
            user_id=user_id, incident_id=incident_id, meta=meta or {},
        )
        inserted = await AlertRepository(db).insert(alert)
        await audit_service.log(
            actor="system", action="alert.raised",
            entity_type="alert", entity_id=str(inserted),
            meta={"kind": kind, "severity": severity},
        )
        return str(inserted)

    async def acknowledge(self, alert_id: str, actor: str) -> bool:
        db = get_db()
        n = await AlertRepository(db).update(
            {"_id": alert_id},
            {"$set": {
                "acknowledged": True,
                "acknowledged_by": actor,
                "acknowledged_at": now_utc(),
            }},
        )
        if n:
            await audit_service.log(
                actor=actor, action="alert.acknowledged",
                entity_type="alert", entity_id=alert_id,
            )
        return bool(n)

    async def active(self, limit: int = 50):
        db = get_db()
        return await AlertRepository(db).active(limit=limit)


alert_service = AlertService()
