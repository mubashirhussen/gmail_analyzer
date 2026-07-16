"""Gmail integration REST endpoints.

Endpoints are authenticated with the platform ``Principal`` (Module 2).
They orchestrate the Gmail auth, sync, label, and monitoring services;
they never touch Google's API directly.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.email_labels import EmailLabelsRepository
from app.repositories.email_threads import EmailThreadsRepository
from app.repositories.gmail_connections import GmailConnectionsRepository
from app.repositories.sync_logs import SyncLogsRepository
from app.schemas.gmail import (GmailConnectCallbackIn, GmailConnectStartIn,
                                GmailConnectStartOut, GmailConnectionOut,
                                GmailStatusOut, GmailSyncTriggerIn,
                                GmailSyncTriggerOut, SyncLogOut)
from app.services.gmail.auth_service import gmail_auth_service
from app.services.gmail.sync_monitoring_service import sync_monitoring_service
from app.services.gmail.sync_service import gmail_sync_service
from app.workers.celery_app import celery

router = APIRouter(prefix="/gmail", tags=["gmail"])


# ---------------------------------------------------------------- connect
@router.post("/connect", response_model=GmailConnectStartOut)
async def connect_start(body: GmailConnectStartIn, _: Principal = CurrentUser):
    url, state = await gmail_auth_service.build_connect_url(redirect_uri=body.redirect_uri)
    return GmailConnectStartOut(authorize_url=url, state=state)


@router.post("/connect/callback", response_model=GmailConnectionOut)
async def connect_callback(body: GmailConnectCallbackIn, p: Principal = CurrentUser):
    conn = await gmail_auth_service.complete_connect(
        user_id=p.user_id, code=body.code, state=body.state,
    )
    # trigger an initial import in the background; UI polls /status
    celery.send_task("gmail.sync_user", args=[p.user_id, "initial"])
    celery.send_task("gmail.sync_labels", args=[p.user_id])
    return _connection_out(conn)


@router.post("/disconnect")
async def disconnect(p: Principal = CurrentUser):
    ok = await gmail_auth_service.disconnect(p.user_id, revoke_at_google=True)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no active Gmail connection")
    return {"ok": True}


@router.post("/reconnect", response_model=GmailConnectStartOut)
async def reconnect(body: GmailConnectStartIn, _: Principal = CurrentUser):
    """Alias for /connect that forces the OAuth consent flow again."""
    url, state = await gmail_auth_service.build_connect_url(redirect_uri=body.redirect_uri)
    return GmailConnectStartOut(authorize_url=url, state=state)


# ------------------------------------------------------------------ status
@router.get("/status", response_model=GmailStatusOut)
async def get_status(p: Principal = CurrentUser):
    data = await sync_monitoring_service.status(p.user_id)
    return GmailStatusOut(**data)


@router.get("/health")
async def health_check(p: Principal = CurrentUser) -> dict[str, Any]:
    conn = await GmailConnectionsRepository(get_db()).get_active_for_user(p.user_id)
    if not conn:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no active Gmail connection")
    try:
        profile = await gmail_auth_service.verify(conn)
        return {"ok": True, "profile": profile}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# -------------------------------------------------------------------- sync
@router.post("/sync", response_model=GmailSyncTriggerOut)
async def trigger_sync(body: GmailSyncTriggerIn, p: Principal = CurrentUser):
    conn = await GmailConnectionsRepository(get_db()).get_active_for_user(p.user_id)
    if not conn:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "gmail not connected")
    if body.async_mode:
        task = celery.send_task("gmail.sync_user", args=[p.user_id, body.kind])
        return GmailSyncTriggerOut(accepted=True, task_id=task.id, status="queued")
    # synchronous (rare — mainly for smoke tests)
    result = await gmail_sync_service.sync_user(p.user_id, kind=body.kind)  # type: ignore[arg-type]
    return GmailSyncTriggerOut(accepted=True, status=result.get("status", "unknown"), detail=result)


@router.get("/sync/history", response_model=list[SyncLogOut])
async def sync_history(p: Principal = CurrentUser,
                        page: int = Query(1, ge=1),
                        page_size: int = Query(20, ge=1, le=100)):
    result = await SyncLogsRepository(get_db()).history(p.user_id, page=page, page_size=page_size)
    return [SyncLogOut(
        id=r.id, kind=r.kind, status=r.status,
        started_at=r.started_at, finished_at=r.finished_at,
        duration_ms=r.duration_ms,
        messages_scanned=r.messages_scanned,
        messages_ingested=r.messages_ingested,
        messages_updated=r.messages_updated,
        messages_skipped=r.messages_skipped,
        api_calls=r.api_calls,
        error_code=r.error_code,
        error_message=r.error_message,
    ) for r in result.items]


# ----------------------------------------------------------------- threads
@router.get("/threads")
async def list_threads(p: Principal = CurrentUser,
                        page: int = Query(1, ge=1),
                        page_size: int = Query(25, ge=1, le=100)):
    page_out = await EmailThreadsRepository(get_db()).list_for_user(
        p.user_id, page=page, page_size=page_size,
    )
    return {
        "items": [t.model_dump() for t in page_out.items],
        "total": page_out.total, "page": page_out.page, "page_size": page_out.page_size,
    }


# ------------------------------------------------------------------ labels
@router.get("/labels")
async def list_labels(p: Principal = CurrentUser):
    labels = await EmailLabelsRepository(get_db()).list_for_user(p.user_id)
    return [l.model_dump() for l in labels]


@router.post("/labels/sync")
async def sync_labels(p: Principal = CurrentUser):
    task = celery.send_task("gmail.sync_labels", args=[p.user_id])
    return {"accepted": True, "task_id": task.id}


# ---------------------------------------------------------------- helpers
def _connection_out(conn) -> GmailConnectionOut:
    return GmailConnectionOut(
        id=conn.id, email=conn.email, status=conn.status,
        scopes=conn.scopes, initial_import_completed=conn.initial_import_completed,
        messages_synced_total=conn.messages_synced_total,
        history_id=conn.history_id,
        last_sync_started_at=conn.last_sync_started_at,
        last_sync_finished_at=conn.last_sync_finished_at,
        last_success_at=conn.last_success_at,
        last_error=conn.last_error,
        connected_at=conn.connected_at,
    )
