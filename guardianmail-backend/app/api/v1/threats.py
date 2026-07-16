"""Threat Intelligence Engine — HTTP surface.

All endpoints require a valid `Principal`; the engine never trusts input
without checking ownership against `user_id`.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.provider_results import ProviderResultRepository
from app.repositories.threat_indicators import ThreatIndicatorRepository
from app.repositories.threat_timeline import ThreatTimelineRepository
from app.repositories.threats import ThreatReportRepository
from app.schemas.threat import (
    ProviderHealthOut,
    RecheckRequest,
    ScanAcceptedOut,
    ScanEmailRequest,
    ScanUrlRequest,
    ThreatReportOut,
)
from app.services.threat.engine_service import threat_engine_service
from app.services.threat.providers import ALL as ALL_PROVIDERS

router = APIRouter(prefix="/threats", tags=["threats"])


# ------------------------------------------------------------------ scans
@router.post("/scan", response_model=ScanAcceptedOut,
             status_code=status.HTTP_202_ACCEPTED)
async def scan_email(body: ScanEmailRequest, p: Principal = CurrentUser) -> ScanAcceptedOut:
    """Synchronously scan an email the user owns.

    For long-running scans callers should prefer the Celery task
    `threat.scan_email` and poll `/threats/{id}`.
    """
    report = await threat_engine_service.scan_email(
        user_id=p.user_id, email_id=body.email_id,
        triggered_by="user_action", force=body.force,
    )
    return ScanAcceptedOut(
        threat_report_id=report.id,
        scan_status=report.scan_status if report.scan_status in ("pending", "running", "completed") else "completed",
        cached=False,
    )


@router.post("/scan-url", response_model=ScanAcceptedOut,
             status_code=status.HTTP_202_ACCEPTED)
async def scan_url(body: ScanUrlRequest, p: Principal = CurrentUser) -> ScanAcceptedOut:
    report = await threat_engine_service.scan_url(
        user_id=p.user_id, url=str(body.url),
        triggered_by="user_action",
    )
    return ScanAcceptedOut(
        threat_report_id=report.id,
        scan_status=report.scan_status if report.scan_status in ("pending", "running", "completed") else "completed",
        cached=False,
    )


@router.post("/recheck", response_model=ScanAcceptedOut)
async def recheck(body: RecheckRequest, p: Principal = CurrentUser) -> ScanAcceptedOut:
    report = await threat_engine_service.recheck(
        user_id=p.user_id, report_id=body.threat_report_id,
    )
    return ScanAcceptedOut(
        threat_report_id=report.id,
        scan_status="completed",
        cached=False,
    )


# ----------------------------------------------------------------- reads
@router.get("/history")
async def list_history(
    p: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    min_risk: float | None = Query(None, ge=0, le=100),
) -> dict[str, Any]:
    repo = ThreatReportRepository(get_db())
    page_res = await repo.list_for_user(
        p.user_id, min_risk=min_risk, page=page, page_size=page_size,
    )
    return {
        "items": [r.model_dump(by_alias=True) for r in page_res.items],
        "total": page_res.total,
        "page": page_res.page,
        "page_size": page_res.page_size,
    }


@router.get("/{report_id}", response_model=ThreatReportOut)
async def get_report(report_id: str, p: Principal = CurrentUser) -> ThreatReportOut:
    repo = ThreatReportRepository(get_db())
    r = await repo.find_by_id(report_id)
    if not r or r.user_id != p.user_id:
        raise HTTPException(status_code=404, detail="report not found")
    return ThreatReportOut.model_validate(r.model_dump(by_alias=True))


@router.get("/{report_id}/report")
async def get_full_report(report_id: str, p: Principal = CurrentUser) -> dict[str, Any]:
    """Report + IOCs + timeline in one call — powers the detail page."""
    db = get_db()
    r = await ThreatReportRepository(db).find_by_id(report_id)
    if not r or r.user_id != p.user_id:
        raise HTTPException(status_code=404, detail="report not found")
    indicators = await ThreatIndicatorRepository(db).for_report(report_id)
    timeline = await ThreatTimelineRepository(db).for_report(report_id)
    return {
        "report": r.model_dump(by_alias=True),
        "indicators": [i.model_dump(by_alias=True) for i in indicators],
        "timeline": [t.model_dump(by_alias=True) for t in timeline],
    }


@router.get("/providers", response_model=list[ProviderHealthOut])
async def provider_status(p: Principal = CurrentUser) -> list[ProviderHealthOut]:
    _ = p  # ownership scope only
    repo = ProviderResultRepository(get_db())
    out: list[ProviderHealthOut] = []
    for prov in ALL_PROVIDERS:
        h = await repo.provider_health(prov.slug, minutes=60)
        out.append(ProviderHealthOut(
            provider=prov.slug,
            enabled=prov.enabled(),
            error_rate_1h=h["error_rate"],
        ))
    return out
