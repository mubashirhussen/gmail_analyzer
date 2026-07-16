"""Phase 18 — SOC API surface.

Endpoints are additive; nothing here changes existing routes. Analyst/admin
operations are gated by a lightweight role check consistent with the rest
of the platform.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.soc import (
    AuditRepository,
    CaseRepository,
    IncidentRepository,
    ReportRepository,
)
from app.schemas.soc import (
    AlertAck,
    CaseCommentIn,
    CaseCreate,
    DashboardOut,
    IncidentAssign,
    IncidentCreate,
    IncidentOut,
    IncidentTransition,
)
from app.services.soc import (
    alert_service,
    audit_service,
    case_service,
    dashboard_service,
    health_service,
    incident_service,
    report_service,
    soc_service,
)


router = APIRouter(prefix="/soc", tags=["soc"])
incidents_router = APIRouter(prefix="/incidents", tags=["soc-incidents"])
alerts_router = APIRouter(prefix="/alerts", tags=["soc-alerts"])
reports_router = APIRouter(prefix="/reports", tags=["soc-reports"])
system_router = APIRouter(prefix="/system", tags=["soc-system"])
audit_router = APIRouter(prefix="/audit", tags=["soc-audit"])
cases_router = APIRouter(prefix="/cases", tags=["soc-cases"])


def _is_analyst(user) -> bool:
    role = getattr(user, "role", None) or getattr(user, "roles", None)
    if isinstance(role, str):
        return role in {"analyst", "soc_analyst", "admin", "super_admin"}
    if isinstance(role, (list, set, tuple)):
        return any(r in {"analyst", "soc_analyst", "admin", "super_admin"} for r in role)
    return bool(getattr(user, "is_admin", False))


def _require_analyst(principal: Principal) -> None:
    if not _is_analyst(principal.user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="analyst_role_required")


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard", response_model=DashboardOut)
async def dashboard(principal: Principal = CurrentUser):
    _require_analyst(principal)
    return await dashboard_service.build()


@router.get("/threat-feed")
async def threat_feed(
    principal: Principal = CurrentUser,
    limit: int = Query(50, ge=1, le=200),
):
    _require_analyst(principal)
    db = get_db()
    cur = (
        db.soc_incidents.find({"deleted_at": None})
        .sort("created_at", -1).limit(limit)
    )
    items = [d async for d in cur]
    return {"items": items, "count": len(items)}


# ---------------------------------------------------------------- incidents
@incidents_router.get("")
async def list_incidents(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: str | None = None,
    incident_status: str | None = Query(None, alias="status"),
    incident_type: str | None = None,
    sender: str | None = None,
    domain: str | None = None,
    since_hours: int | None = Query(None, ge=1, le=24 * 365),
    mine: bool = False,
):
    db = get_db()
    since = datetime.utcnow() - timedelta(hours=since_hours) if since_hours else None
    user_filter = principal.user_id if (mine or not _is_analyst(principal.user)) else None
    return await IncidentRepository(db).list_filtered(
        user_id=user_filter, severity=severity, status=incident_status,
        incident_type=incident_type, sender=sender, domain=domain,
        since=since, page=page, page_size=page_size,
    )


@incidents_router.post("", response_model=IncidentOut, status_code=201)
async def create_incident(body: IncidentCreate, principal: Principal = CurrentUser):
    _require_analyst(principal)
    doc = await incident_service.create(
        user_id=body.user_id or principal.user_id,
        source=body.source, source_ref=body.source_ref,
        incident_type=body.incident_type,
        threat_category=body.threat_category,
        severity=body.severity, confidence=body.confidence,
        risk_score=body.risk_score, subject=body.subject,
        sender=body.sender, domain=body.domain, urls=body.urls,
        attachments=body.attachments, tags=body.tags, evidence=body.evidence,
        actor=principal.user_id,
    )
    return doc


@incidents_router.get("/{incident_id}")
async def get_incident(incident_id: str, principal: Principal = CurrentUser):
    db = get_db()
    doc = await IncidentRepository(db).find_by_id(incident_id)
    if not doc:
        raise HTTPException(404, "incident_not_found")
    if doc.user_id != principal.user_id and not _is_analyst(principal.user):
        raise HTTPException(403, "forbidden")
    return doc.model_dump(by_alias=True)


@incidents_router.patch("/{incident_id}")
async def transition_incident(
    incident_id: str,
    body: IncidentTransition,
    principal: Principal = CurrentUser,
):
    _require_analyst(principal)
    return await incident_service.transition(
        incident_id, new_status=body.status, actor=principal.user_id,
        note=body.note, resolution=body.resolution,
    )


@incidents_router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    body: IncidentAssign,
    principal: Principal = CurrentUser,
):
    _require_analyst(principal)
    await incident_service.assign(
        incident_id, assignee=body.assigned_to, actor=principal.user_id,
    )
    return {"ok": True}


@incidents_router.get("/{incident_id}/timeline")
async def incident_timeline(incident_id: str, principal: Principal = CurrentUser):
    db = get_db()
    doc = await IncidentRepository(db).find_by_id(incident_id)
    if not doc:
        raise HTTPException(404, "incident_not_found")
    if doc.user_id != principal.user_id and not _is_analyst(principal.user):
        raise HTTPException(403, "forbidden")
    return {"items": await incident_service.get_timeline(incident_id)}


# ---------------------------------------------------------------- cases
@cases_router.post("", status_code=201)
async def open_case(body: CaseCreate, principal: Principal = CurrentUser):
    _require_analyst(principal)
    return await case_service.open_case(
        incident_id=body.incident_id, title=body.title,
        priority=body.priority, owner=body.owner, actor=principal.user_id,
    )


@cases_router.get("/{case_id}")
async def get_case(case_id: str, principal: Principal = CurrentUser):
    _require_analyst(principal)
    doc = await case_service.get(case_id)
    if not doc:
        raise HTTPException(404, "case_not_found")
    return doc


@cases_router.post("/{case_id}/comment")
async def comment_case(
    case_id: str, body: CaseCommentIn, principal: Principal = CurrentUser,
):
    _require_analyst(principal)
    await case_service.add_comment(
        case_id, author=body.author or principal.user_id, body=body.body,
    )
    return {"ok": True}


# ---------------------------------------------------------------- alerts
@alerts_router.get("")
async def list_alerts(
    principal: Principal = CurrentUser, limit: int = Query(50, ge=1, le=200),
):
    _require_analyst(principal)
    return {"items": await alert_service.active(limit=limit)}


@alerts_router.post("/{alert_id}/ack")
async def ack_alert(
    alert_id: str, _: AlertAck = AlertAck(), principal: Principal = CurrentUser,
):
    _require_analyst(principal)
    ok = await alert_service.acknowledge(alert_id, actor=principal.user_id)
    if not ok:
        raise HTTPException(404, "alert_not_found")
    return {"ok": True}


# ---------------------------------------------------------------- reports
@reports_router.get("")
async def list_reports(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    _require_analyst(principal)
    return await report_service.list_reports(page=page, page_size=page_size)


@reports_router.post("/generate")
async def generate_report(
    kind: str = Query("daily", pattern="^(daily|weekly|monthly|adhoc)$"),
    principal: Principal = CurrentUser,
):
    _require_analyst(principal)
    return await report_service.generate(kind=kind, generated_by=principal.user_id)


# ---------------------------------------------------------------- system
@system_router.get("/health")
async def system_health(principal: Principal = CurrentUser):
    _require_analyst(principal)
    latest = await health_service.latest()
    if not latest:
        latest = await health_service.snapshot_all()
    return {"components": latest, "checked_at": datetime.utcnow()}


@system_router.post("/health/refresh")
async def refresh_health(principal: Principal = CurrentUser):
    _require_analyst(principal)
    return {"components": await health_service.snapshot_all()}


# ---------------------------------------------------------------- audit
@audit_router.get("")
async def list_audit(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: str | None = None,
    entity_id: str | None = None,
):
    _require_analyst(principal)
    db = get_db()
    f: dict = {}
    if action:
        f["action"] = action
    if entity_id:
        f["entity_id"] = entity_id
    return await AuditRepository(db).paginate(
        f, page=page, page_size=page_size,
    )
