"""Case management service."""
from __future__ import annotations

from typing import Any

from app.core.clock import now_utc
from app.core.exceptions import NotFoundError
from app.database.mongodb import get_db
from app.models.soc import Case
from app.repositories.soc import CaseRepository, IncidentRepository
from app.services.soc.audit_service import audit_service


class CaseManagementService:
    async def open_case(
        self,
        *,
        incident_id: str,
        title: str,
        actor: str,
        priority: str = "p3",
        owner: str | None = None,
    ) -> dict[str, Any]:
        db = get_db()
        inc = await IncidentRepository(db).find_by_id(incident_id)
        if not inc:
            raise NotFoundError("incident_not_found")
        existing = await CaseRepository(db).for_incident(incident_id)
        if existing:
            return existing
        case = Case(
            incident_id=incident_id, user_id=inc.user_id, title=title,
            priority=priority, owner=owner or actor,
            history=[{"at": now_utc().isoformat(), "actor": actor,
                      "action": "case_opened"}],
        )
        inserted = await CaseRepository(db).insert(case)
        await audit_service.log(
            actor=actor, action="case.opened",
            entity_type="case", entity_id=str(inserted),
            meta={"incident_id": incident_id, "priority": priority},
        )
        return (await CaseRepository(db).find_by_id(str(inserted))).model_dump(by_alias=True)

    async def add_comment(self, case_id: str, *, author: str, body: str) -> None:
        db = get_db()
        await CaseRepository(db).update(
            {"_id": case_id},
            {"$push": {"comments": {
                "at": now_utc().isoformat(), "author": author, "body": body,
            }}},
        )
        await audit_service.log(
            actor=author, action="case.comment",
            entity_type="case", entity_id=case_id,
        )

    async def get(self, case_id: str) -> dict[str, Any] | None:
        db = get_db()
        doc = await CaseRepository(db).find_by_id(case_id)
        return doc.model_dump(by_alias=True) if doc else None


case_service = CaseManagementService()
