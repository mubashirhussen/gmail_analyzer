"""Phase 19 — observability API surface.

Additive endpoints for the observability platform. Existing ``/metrics``
and ``/healthz`` routes in ``app.api`` remain untouched.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Body, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.observability import (
    ObservabilityAlertRepository,
    OpsIncidentRepository,
    TelemetryRepository,
)
from app.services.observability import (
    metrics_service,
    observability_service,
    ops_alert_service,
    ops_health_service,
    ops_incident_service,
    telemetry_service,
)

router = APIRouter(prefix="/observability", tags=["observability"])
metrics_router = APIRouter(prefix="/metrics", tags=["observability-metrics"])
traces_router = APIRouter(prefix="/traces", tags=["observability-traces"])
system_router = APIRouter(prefix="/system", tags=["observability-system"])
ops_incidents_router = APIRouter(prefix="/ops/incidents", tags=["ops-incidents"])
ops_alerts_router = APIRouter(prefix="/ops/alerts", tags=["ops-alerts"])


def _is_ops(user) -> bool:
    role = getattr(user, "role", None) or getattr(user, "roles", None)
    allowed = {"admin", "super_admin", "sre", "devops", "soc_analyst"}
    if isinstance(role, str):
        return role in allowed
    if isinstance(role, (list, set, tuple)):
        return any(r in allowed for r in role)
    return bool(getattr(user, "is_admin", False))


def _require_ops(principal: Principal) -> None:
    if not _is_ops(principal.user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "ops_role_required")


# ---------------------------------------------------------------- metrics
@metrics_router.get("/summary")
async def metrics_summary(principal: Principal = CurrentUser):
    _require_ops(principal)
    db = get_db()
    active_alerts = await ObservabilityAlertRepository(db).active(limit=100)
    open_incidents = await OpsIncidentRepository(db).open_incidents()
    return {
        "generated_at": datetime.utcnow(),
        "active_alerts": len(active_alerts),
        "open_incidents": len(open_incidents),
        "components": (await ops_health_service.probe_all()),
    }


# ---------------------------------------------------------------- traces
@traces_router.get("")
async def list_traces(
    principal: Principal = CurrentUser,
    limit: int = Query(50, ge=1, le=200),
):
    _require_ops(principal)
    return {"items": await telemetry_service.recent(limit=limit)}


@traces_router.get("/{trace_id}")
async def get_trace(trace_id: str, principal: Principal = CurrentUser):
    _require_ops(principal)
    spans = await telemetry_service.for_trace(trace_id)
    if not spans:
        raise HTTPException(404, "trace_not_found")
    return {"trace_id": trace_id, "spans": spans}


# ---------------------------------------------------------------- system
@system_router.get("/status")
async def system_status(principal: Principal = CurrentUser):
    _require_ops(principal)
    components = await ops_health_service.probe_all()
    down = [c for c, r in components.items() if r.get("status") != "healthy"]
    return {
        "generated_at": datetime.utcnow(),
        "healthy": not down,
        "components": components,
        "degraded_components": down,
    }


# ---------------------------------------------------------------- alerts
@ops_alerts_router.post("/webhook")
async def alertmanager_webhook(payload: dict = Body(...)):
    """AlertManager webhook — no auth (network-scoped in prod)."""
    count = await ops_alert_service.ingest_alertmanager(payload)
    return {"ingested": count}


@ops_alerts_router.get("")
async def list_alerts(
    principal: Principal = CurrentUser,
    limit: int = Query(100, ge=1, le=500),
):
    _require_ops(principal)
    return {"items": await ops_alert_service.active(limit=limit)}


@ops_alerts_router.post("/{fingerprint}/resolve")
async def resolve_alert(fingerprint: str, principal: Principal = CurrentUser):
    _require_ops(principal)
    ok = await ops_alert_service.resolve(fingerprint)
    if not ok:
        raise HTTPException(404, "alert_not_found")
    return {"ok": True}


# ---------------------------------------------------------------- incidents
@ops_incidents_router.get("")
async def list_ops_incidents(principal: Principal = CurrentUser):
    _require_ops(principal)
    return {"items": await ops_incident_service.list_open()}


@ops_incidents_router.get("/{incident_id}")
async def get_ops_incident(incident_id: str, principal: Principal = CurrentUser):
    _require_ops(principal)
    doc = await ops_incident_service.get(incident_id)
    if not doc:
        raise HTTPException(404, "ops_incident_not_found")
    return doc


@ops_incidents_router.post("/{incident_id}/resolve")
async def resolve_ops_incident(
    incident_id: str,
    root_cause: str | None = Body(None, embed=True),
    principal: Principal = CurrentUser,
):
    _require_ops(principal)
    await ops_incident_service.resolve(incident_id, root_cause=root_cause)
    return {"ok": True}


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
async def obs_dashboard(principal: Principal = CurrentUser):
    _require_ops(principal)
    db = get_db()
    since = datetime.utcnow() - timedelta(hours=24)
    return {
        "generated_at": datetime.utcnow(),
        "components": await ops_health_service.probe_all(),
        "active_alerts": await ops_alert_service.active(limit=25),
        "open_incidents": await ops_incident_service.list_open(),
        "recent_traces": await telemetry_service.recent(limit=25),
        "since": since,
    }
