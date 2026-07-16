"""Operational incident service — auto-open ops incidents from alerts.

Distinct from Module 18's SOC ``incident_service``: SOC handles *security*
incidents (phishing/BEC/etc.); this service tracks *infrastructure*
incidents (API down, DB down, latency, error-rate spikes). Both feed the
enterprise incident dashboard.
"""
from __future__ import annotations

from typing import Any

from app.core.clock import now_utc
from app.core.exceptions import NotFoundError
from app.database.mongodb import get_db
from app.models.observability import OperationalIncident
from app.repositories.observability import OpsIncidentRepository


class OpsIncidentService:
    async def open(
        self,
        *,
        kind: str,
        title: str,
        severity: str = "high",
        summary: str = "",
        affected: list[str] | None = None,
        suggested_resolution: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        db = get_db()
        repo = OpsIncidentRepository(db)
        # dedupe on (kind, active title) to avoid noise storms
        existing = await repo.find_one(
            {"kind": kind, "status": {"$ne": "resolved"}},
        )
        if existing:
            await repo.update(
                {"_id": existing.id},
                {"$push": {"timeline": {
                    "at": now_utc().isoformat(),
                    "event": "recurrence",
                    "summary": summary,
                }}},
            )
            return existing.model_dump(by_alias=True)
        inc = OperationalIncident(
            kind=kind, severity=severity, title=title, summary=summary,
            affected=affected or [], suggested_resolution=suggested_resolution,
            meta=meta or {},
            timeline=[{
                "at": now_utc().isoformat(), "event": "opened",
                "summary": summary,
            }],
        )
        inserted = await repo.insert(inc)
        return (await repo.find_by_id(str(inserted))).model_dump(by_alias=True)

    async def resolve(self, incident_id: str, *, root_cause: str | None = None) -> None:
        db = get_db()
        repo = OpsIncidentRepository(db)
        current = await repo.find_by_id(incident_id)
        if not current:
            raise NotFoundError("ops_incident_not_found")
        await repo.update(
            {"_id": incident_id},
            {"$set": {
                "status": "resolved",
                "recovered_at": now_utc(),
                "root_cause": root_cause,
            }, "$push": {"timeline": {
                "at": now_utc().isoformat(), "event": "resolved",
                "summary": root_cause or "",
            }}},
        )

    async def list_open(self) -> list[dict[str, Any]]:
        db = get_db()
        return await OpsIncidentRepository(db).open_incidents()

    async def get(self, incident_id: str) -> dict[str, Any] | None:
        db = get_db()
        doc = await OpsIncidentRepository(db).find_by_id(incident_id)
        return doc.model_dump(by_alias=True) if doc else None


ops_incident_service = OpsIncidentService()
