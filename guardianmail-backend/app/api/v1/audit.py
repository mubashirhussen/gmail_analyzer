"""Query + filter audit logs and security/device-change alerts.

Filters: user (via bearer), date range, threat category, severity, kind.
"""
from __future__ import annotations

from datetime import datetime
from fastapi import APIRouter, Depends, Query

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs")
async def logs(
    user=Depends(require_user), db=Depends(get_db),
    start: datetime | None = Query(None),
    end: datetime | None = Query(None),
    event: str | None = None,
    severity: str | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    q: dict = {"user_id": user["sub"]}
    if start or end:
        q["at"] = {}
        if start: q["at"]["$gte"] = start
        if end:   q["at"]["$lte"] = end
    if event:    q["event"] = event
    if severity: q["severity"] = severity
    cur = db.audit_logs.find(q).sort("at", -1).limit(limit)
    return [{**d, "_id": str(d["_id"])} async for d in cur]


@router.get("/alerts")
async def alerts(
    user=Depends(require_user), db=Depends(get_db),
    start: datetime | None = None,
    end: datetime | None = None,
    category: str | None = Query(None, description="phishing|fraud|suspicious|device_change|..."),
    severity: str | None = None,
    kind: str | None = Query(None, description="suspicious_artifact|new_device|device_revoked|..."),
    limit: int = Query(100, ge=1, le=500),
):
    q: dict = {"user_id": user["sub"]}
    if start or end:
        q["created_at"] = {}
        if start: q["created_at"]["$gte"] = start
        if end:   q["created_at"]["$lte"] = end
    if category: q["meta.category"] = category
    if severity: q["severity"] = severity
    if kind:     q["kind"] = kind
    cur = db.security_events.find(q).sort("created_at", -1).limit(limit)
    return [{**d, "_id": str(d["_id"])} async for d in cur]


@router.get("/device/{fingerprint}/artifacts")
async def device_artifacts(
    fingerprint: str, user=Depends(require_user), db=Depends(get_db),
    verdict: str | None = None, limit: int = Query(50, ge=1, le=200),
):
    q: dict = {"user_id": user["sub"], "device_fingerprint": fingerprint}
    if verdict: q["verdict"] = verdict
    cur = db.device_artifacts.find(q).sort("at", -1).limit(limit)
    return [{**d, "_id": str(d["_id"])} async for d in cur]
