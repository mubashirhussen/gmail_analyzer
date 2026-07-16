"""Task platform REST API.

All endpoints require an authenticated `Principal`. The `dispatch` endpoint
restricts task names to a small allow-list — arbitrary Celery task names
must never be user-controllable.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import Principal, get_principal
from app.database.mongodb import get_db
from app.repositories.background_jobs import BackgroundJobRepository
from app.schemas.base import Page
from app.schemas.tasks import (
    DeadLetterEntry, DispatchRequest, DispatchResponse, JobView,
    PlatformHealth, QueueDepthResponse, WorkersResponse,
)
from app.services.tasks import dead_letter
from app.services.tasks.dispatcher import TaskDispatcherService
from app.services.tasks.monitoring import MonitoringService
from app.services.tasks.priority import TaskPriority

router = APIRouter(prefix="/tasks", tags=["tasks"])

# Only these task names can be dispatched from the API. Business tasks that
# should never be user-triggered (e.g. maintenance sweeps) stay off the list.
ALLOWED_TASKS: set[str] = {
    "gmail.sync_user",
    "ocr.process_upload",
    "threat.rescan",
    "ai.reanalyze",
    "analytics.recalculate",
    "notifications.send",
    "reports.weekly_digest",
    "complaints.regenerate",
}


def _to_view(job) -> JobView:
    return JobView(
        id=job.id, job_type=job.job_type, status=job.status,
        queue=job.queue, user_id=job.user_id, task_id=job.task_id,
        retry_count=job.retry_count, max_retries=job.max_retries,
        result=job.result, error=job.error,
        created_at=job.created_at, started_at=job.started_at,
        finished_at=job.finished_at, duration_ms=job.duration_ms,
    )


# --------------------------------------------------------------- dispatch
@router.post("/run", response_model=DispatchResponse)
async def dispatch(
    body: DispatchRequest,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> DispatchResponse:
    if body.task_name not in ALLOWED_TASKS:
        raise HTTPException(403, f"task '{body.task_name}' is not user-dispatchable")
    dispatcher = TaskDispatcherService(db)
    result = await dispatcher.dispatch(
        task_name=body.task_name,
        args=body.args,
        kwargs=body.kwargs,
        user_id=principal.user_id,
        queue=body.queue,
        priority=TaskPriority(body.priority),
        dedup_key=body.dedup_key,
        max_retries=body.max_retries,
        countdown=body.countdown,
    )
    return DispatchResponse(
        job_id=result.job_id, task_id=result.task_id,
        queue=result.queue, priority=result.priority, status=result.status,
    )


# ---------------------------------------------------------------- reads
@router.get("/{job_id}", response_model=JobView)
async def get_job(
    job_id: str,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> JobView:
    job = await BackgroundJobRepository(db).find_by_id(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    if job.user_id and job.user_id != principal.user_id:
        raise HTTPException(404, "job not found")
    return _to_view(job)


@router.get("/history/list", response_model=Page[JobView])
async def history(
    status: str | None = None,
    page: int = 1,
    page_size: int = 25,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> Page[JobView]:
    p = await BackgroundJobRepository(db).list_for_user(
        principal.user_id, status=status,  # type: ignore[arg-type]
        page=page, page_size=page_size,
    )
    return Page[JobView](
        items=[_to_view(j) for j in p.items],
        total=p.total, page=p.page, page_size=p.page_size,
    )


# ---------------------------------------------------------------- retry / cancel
@router.post("/{job_id}/retry", response_model=DispatchResponse)
async def retry(
    job_id: str,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> DispatchResponse:
    dispatcher = TaskDispatcherService(db)
    job = await BackgroundJobRepository(db).find_by_id(job_id)
    if not job or (job.user_id and job.user_id != principal.user_id):
        raise HTTPException(404, "job not found")
    r = await dispatcher.retry_job(job_id)
    if not r:
        raise HTTPException(409, "job not retryable")
    return DispatchResponse(
        job_id=r.job_id, task_id=r.task_id,
        queue=r.queue, priority=r.priority, status=r.status,
    )


@router.delete("/{job_id}")
async def cancel(
    job_id: str,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> dict:
    ok = await TaskDispatcherService(db).cancel(job_id, principal.user_id)
    if not ok:
        raise HTTPException(404, "job not found or not cancellable")
    return {"cancelled": True}


# ------------------------------------------------------------- monitoring
@router.get("/platform/health", response_model=PlatformHealth)
async def platform_health(
    _: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> PlatformHealth:
    h = await MonitoringService(db).platform_health()
    return PlatformHealth(**h)


@router.get("/platform/queues", response_model=QueueDepthResponse)
async def queues(
    _: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> QueueDepthResponse:
    depths = await MonitoringService(db).queue_depths()
    return QueueDepthResponse(depths=depths)


@router.get("/platform/workers", response_model=WorkersResponse)
async def workers(
    _: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> WorkersResponse:
    return WorkersResponse(workers=await MonitoringService(db).workers())


@router.get("/platform/dead-letter", response_model=list[DeadLetterEntry])
async def dead_letter_peek(
    limit: int = 50,
    _: Principal = Depends(get_principal),
) -> list[DeadLetterEntry]:
    entries = await dead_letter.peek(count=min(max(1, limit), 200))
    return [DeadLetterEntry(**{k: str(v) for k, v in e.items()}) for e in entries]
