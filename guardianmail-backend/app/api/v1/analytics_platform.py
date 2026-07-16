"""API routers for the Analytics, Dashboard, and Reporting Platform (Module 10).

Three routers are exposed:

* `router`            — /api/v1/dashboard-platform    (KPI, overview, scoped)
* `analytics_router`  — /api/v1/analytics-platform    (per-domain analytics + trends)
* `reports_router`    — /api/v1/reports-platform      (report lifecycle + download)

All endpoints are protected by JWT auth via `require_user`. Reads are cached
in Redis; report generation dispatches through Celery.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.security import require_user
from app.database.mongodb import get_db
from app.schemas.analytics_platform import (
    DashboardOverview, ReportGenerateRequest, ReportSummary, TimeFilter,
)
from app.services.analytics_platform.analytics_service import AnalyticsService
from app.services.analytics_platform.dashboard_service import DashboardService
from app.services.analytics_platform.reporting_service import ReportingService
from app.services.analytics_platform.time_filters import TimeFilterService
from app.services.analytics_platform.trend_service import TrendService
from app.workers.celery_app import celery

# ============================================================ dashboards
router = APIRouter(prefix="/dashboard-platform", tags=["dashboard-platform"])


def _tr(
    time_filter: TimeFilter,
    since: datetime | None,
    until: datetime | None,
):
    return TimeFilterService().resolve(time_filter, since=since, until=until)


@router.get("/overview", response_model=DashboardOverview)
async def overview(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None,
    until: datetime | None = None,
    refresh: bool = False,
    user=Depends(require_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
) -> DashboardOverview:
    tr = _tr(time_filter, since, until)
    service = DashboardService(db)
    return await service.overview(user["sub"], tr, use_cache=not refresh)


@router.get("/scope/{scope}")
async def scoped(
    scope: Literal["security", "threats", "emails", "domains",
                   "users", "ai", "ocr", "complaints"],
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None,
    until: datetime | None = None,
    user=Depends(require_user),
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    service = DashboardService(db)
    try:
        return await service.scoped(user["sub"], scope, tr)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/invalidate")
async def invalidate_cache(user=Depends(require_user),
                            db: AsyncIOMotorDatabase = Depends(get_db)):
    service = DashboardService(db)
    n = await service.invalidate_user(user["sub"])
    return {"invalidated": n}


# ============================================================ analytics
analytics_router = APIRouter(prefix="/analytics-platform", tags=["analytics-platform"])


@analytics_router.get("/emails")
async def emails_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).email_analytics(user["sub"], tr)


@analytics_router.get("/threats")
async def threats_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).threat_analytics(user["sub"], tr)


@analytics_router.get("/security")
async def security_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).security_analytics(user["sub"], tr)


@analytics_router.get("/users")
async def user_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).user_analytics(user["sub"], tr)


@analytics_router.get("/domains")
async def domain_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).domain_analytics(user["sub"], tr)


@analytics_router.get("/ai")
async def ai_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).ai_analytics(user["sub"], tr)


@analytics_router.get("/ocr")
async def ocr_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).ocr_analytics(user["sub"], tr)


@analytics_router.get("/complaints")
async def complaint_analytics(
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    return await AnalyticsService(db).complaint_analytics(user["sub"], tr)


@analytics_router.get("/trends/{metric}")
async def trend(
    metric: str,
    time_filter: TimeFilter = "last_30_days",
    since: datetime | None = None, until: datetime | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    tr = _tr(time_filter, since, until)
    service = TrendService(db)
    chart = await service.read(user["sub"], metric, tr)
    if not chart.series[0].points:
        # lazy compute if the trend series is empty
        await service.build_metric(user["sub"], metric, tr)
        chart = await service.read(user["sub"], metric, tr)
    return chart


@analytics_router.post("/trends/rebuild")
async def rebuild_trends(user=Depends(require_user)):
    task = celery.send_task("analytics_platform.build_trends",
                            args=[user["sub"]], queue="analytics")
    return {"task_id": task.id}


# ============================================================ reports
reports_router = APIRouter(prefix="/reports-platform", tags=["reports-platform"])


@reports_router.post("/generate")
async def generate(
    req: ReportGenerateRequest,
    sync: bool = Query(False, description="Render inline (small reports only)"),
    user=Depends(require_user), db=Depends(get_db),
):
    service = ReportingService(db)
    rec = await service.create_pending(user["sub"], req)
    if sync:
        rec = await service.generate_now(rec.id)
        return service._summary(rec)
    task = celery.send_task("analytics_platform.generate_report",
                            args=[rec.id], queue="analytics")
    return {"report_id": rec.id, "task_id": task.id,
            "status": "queued"}


@reports_router.get("", response_model=list[ReportSummary])
async def list_reports(
    kind: str | None = None,
    user=Depends(require_user), db=Depends(get_db),
):
    return await ReportingService(db).list_for_user(user["sub"], kind=kind)


@reports_router.get("/{report_id}", response_model=ReportSummary)
async def get_report(
    report_id: str,
    user=Depends(require_user), db=Depends(get_db),
):
    service = ReportingService(db)
    rec = await service.repo.find_by_id(report_id)
    if not rec or rec.user_id != user["sub"]:
        raise HTTPException(404, "report not found")
    return service._summary(rec)


@reports_router.get("/download/{token}")
async def download(token: str, db=Depends(get_db)):
    """Anonymous token-authenticated download of a generated report.

    Tokens are single-use per issue (short-lived, per-report, unguessable).
    The report record links the token back to its owner for audit logging.
    """
    service = ReportingService(db)
    try:
        data, mime, rec = await service.download(token)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    ext_map = {"application/pdf": "pdf", "text/csv": "csv",
               "application/json": "json"}
    ext = ext_map.get(mime, rec.fmt)
    filename = f"guardianmail_{rec.kind}_{rec.id[:8]}.{ext}"
    return Response(
        content=data, media_type=mime,
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )
