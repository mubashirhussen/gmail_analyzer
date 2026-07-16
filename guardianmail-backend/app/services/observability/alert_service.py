"""Operational alert intake service.

Accepts AlertManager webhook payloads plus internally-raised alerts, and
persists them as ``ObservabilityAlert`` documents. Duplicate fingerprints
update the existing row rather than creating a new one.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Iterable

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.observability import ObservabilityAlert
from app.repositories.observability import ObservabilityAlertRepository

_log = get_logger(__name__)


def _fingerprint(rule: str, labels: dict[str, Any]) -> str:
    keys = sorted((k, str(v)) for k, v in labels.items())
    return hashlib.sha1(
        f"{rule}|{keys}".encode("utf-8"), usedforsecurity=False,
    ).hexdigest()


class OpsAlertService:
    async def ingest_alertmanager(self, payload: dict[str, Any]) -> int:
        alerts: Iterable[dict[str, Any]] = payload.get("alerts") or []
        count = 0
        for a in alerts:
            await self._upsert(
                rule=a.get("labels", {}).get("alertname", "unknown"),
                severity=a.get("labels", {}).get("severity", "high"),
                component=a.get("labels", {}).get("component", "unknown"),
                summary=a.get("annotations", {}).get("summary", ""),
                description=a.get("annotations", {}).get("description", ""),
                labels=a.get("labels", {}),
                annotations=a.get("annotations", {}),
                status=a.get("status", "firing"),
                starts_at=a.get("startsAt"),
                ends_at=a.get("endsAt"),
            )
            count += 1
        return count

    async def raise_internal(
        self,
        *,
        rule: str,
        severity: str,
        component: str,
        summary: str,
        description: str = "",
        labels: dict[str, Any] | None = None,
    ) -> str:
        return await self._upsert(
            rule=rule, severity=severity, component=component,
            summary=summary, description=description,
            labels=labels or {}, annotations={}, status="firing",
        )

    async def resolve(self, fingerprint: str) -> bool:
        db = get_db()
        n = await ObservabilityAlertRepository(db).update(
            {"fingerprint": fingerprint, "active": True},
            {"$set": {"active": False, "resolved_at": now_utc()}},
        )
        return bool(n)

    async def active(self, limit: int = 100) -> list[dict[str, Any]]:
        db = get_db()
        return await ObservabilityAlertRepository(db).active(limit=limit)

    async def _upsert(
        self,
        *,
        rule: str,
        severity: str,
        component: str,
        summary: str,
        description: str,
        labels: dict[str, Any],
        annotations: dict[str, Any],
        status: str,
        starts_at: str | None = None,
        ends_at: str | None = None,
    ) -> str:
        db = get_db()
        repo = ObservabilityAlertRepository(db)
        fp = _fingerprint(rule, labels)
        existing = await repo.find_one({"fingerprint": fp})
        if existing:
            if status == "resolved":
                await repo.update(
                    {"fingerprint": fp},
                    {"$set": {"active": False, "resolved_at": now_utc()}},
                )
            return existing.id
        alert = ObservabilityAlert(
            rule=rule, severity=severity, component=component,
            summary=summary, description=description,
            fingerprint=fp, labels=labels, annotations=annotations,
            active=(status != "resolved"),
        )
        inserted = await repo.insert(alert)
        return str(inserted)


ops_alert_service = OpsAlertService()
