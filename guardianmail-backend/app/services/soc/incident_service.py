"""Incident service — lifecycle, timeline, transitions.

All writes emit an audit-log entry. State transitions are validated against
an allowed-set to keep the workflow deterministic.
"""
from __future__ import annotations

from typing import Any

from app.core.clock import now_utc
from app.core.exceptions import ConflictError, NotFoundError
from app.database.mongodb import get_db
from app.models.soc import Incident, IncidentTimelineEntry
from app.repositories.soc import IncidentRepository, TimelineRepository
from app.services.soc.audit_service import audit_service


ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "new": {"investigating", "closed"},
    "investigating": {"awaiting_review", "escalated", "resolved", "closed"},
    "awaiting_review": {"investigating", "escalated", "resolved", "closed"},
    "escalated": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
}


def _severity_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


class IncidentService:
    async def create(
        self,
        *,
        user_id: str,
        source: str = "detection",
        source_ref: str | None = None,
        incident_type: str = "phishing",
        threat_category: str | None = None,
        severity: str | None = None,
        confidence: float = 0.5,
        risk_score: float = 50.0,
        subject: str | None = None,
        sender: str | None = None,
        domain: str | None = None,
        urls: list[str] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        tags: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        actor: str = "system",
    ) -> dict[str, Any]:
        db = get_db()
        sev = severity or _severity_from_score(risk_score)
        inc = Incident(
            user_id=user_id, source=source, source_ref=source_ref,
            incident_type=incident_type, threat_category=threat_category,
            severity=sev, confidence=max(0.0, min(1.0, confidence)),
            risk_score=max(0.0, min(100.0, risk_score)),
            subject=subject, sender=(sender or None) and sender.lower(),
            domain=(domain or None) and domain.lower(),
            urls=urls or [], attachments=attachments or [],
            tags=tags or [], evidence=evidence or [],
        )
        inserted = await IncidentRepository(db).insert(inc)
        incident_id = str(inserted)
        await self._timeline(
            incident_id, step="incident_created", actor=actor,
            summary=f"Incident created from {source}",
            payload={"source_ref": source_ref, "risk_score": risk_score},
        )
        await audit_service.log(
            actor=actor, action="incident.created",
            entity_type="incident", entity_id=incident_id, user_id=user_id,
            meta={"severity": sev, "risk_score": risk_score, "source": source},
        )
        doc = await IncidentRepository(db).find_by_id(incident_id)
        return doc.model_dump(by_alias=True) if doc else {"_id": incident_id}

    async def transition(
        self,
        incident_id: str,
        *,
        new_status: str,
        actor: str,
        note: str | None = None,
        resolution: str | None = None,
    ) -> dict[str, Any]:
        db = get_db()
        repo = IncidentRepository(db)
        current = await repo.find_by_id(incident_id)
        if not current:
            raise NotFoundError("incident_not_found")
        cur_status = current.status
        if new_status == cur_status:
            return current.model_dump(by_alias=True)
        allowed = ALLOWED_TRANSITIONS.get(cur_status, set())
        if new_status not in allowed:
            raise ConflictError(
                f"invalid_transition:{cur_status}->{new_status}"
            )
        set_ops: dict[str, Any] = {"status": new_status}
        if resolution is not None:
            set_ops["resolution"] = resolution
        if new_status == "resolved":
            set_ops["resolved_at"] = now_utc()
        if new_status == "closed":
            set_ops["closed_at"] = now_utc()
        await repo.update({"_id": incident_id}, {"$set": set_ops})
        await self._timeline(
            incident_id, step=f"status_{new_status}", actor=actor,
            summary=note or f"transitioned to {new_status}",
            payload={"from": cur_status, "to": new_status,
                     "resolution": resolution},
        )
        await audit_service.log(
            actor=actor, action="incident.transition",
            entity_type="incident", entity_id=incident_id,
            meta={"from": cur_status, "to": new_status},
        )
        return (await repo.find_by_id(incident_id)).model_dump(by_alias=True)

    async def assign(self, incident_id: str, *, assignee: str, actor: str) -> None:
        db = get_db()
        await IncidentRepository(db).update(
            {"_id": incident_id}, {"$set": {"assigned_to": assignee}}
        )
        await self._timeline(
            incident_id, step="assigned", actor=actor,
            summary=f"assigned to {assignee}",
        )
        await audit_service.log(
            actor=actor, action="incident.assigned",
            entity_type="incident", entity_id=incident_id,
            meta={"assignee": assignee},
        )

    async def get_timeline(self, incident_id: str) -> list[dict[str, Any]]:
        db = get_db()
        return await TimelineRepository(db).for_incident(incident_id)

    async def _timeline(
        self,
        incident_id: str,
        *,
        step: str,
        actor: str,
        summary: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        db = get_db()
        entry = IncidentTimelineEntry(
            incident_id=incident_id, step=step, actor=actor,
            summary=summary, payload=payload or {},
        )
        await TimelineRepository(db).insert(entry)


incident_service = IncidentService()
