"""AI Analysis Engine REST endpoints (Module 6).

All endpoints require an authenticated `Principal` and scope every
lookup to `principal.user_id` so a user can never read another user's
AI reports.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import Principal, get_principal
from app.core.exceptions import NotFoundError
from app.database.mongodb import get_db
from app.repositories.ai_decisions import AIDecisionHistoryRepository
from app.repositories.ai_reports import AIReportRepository
from app.schemas.ai import AIAnalyzeRequest, AIModelInfo, AIReportDTO
from app.services.ai.ai_analysis_service import AIAnalysisService
from app.services.ai.config import config

router = APIRouter(prefix="/ai", tags=["ai"])


def _to_dto(report) -> dict:
    return AIReportDTO.model_validate(report.model_dump(by_alias=True)).model_dump(
        by_alias=True,
    )


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze(body: AIAnalyzeRequest, principal: Principal = Depends(get_principal)):
    try:
        service = AIAnalysisService()
        report = await service.analyze(
            user_id=principal.user_id,
            threat_report_id=body.threat_report_id,
            channel=body.channel,
            triggered_by="user",
            force=body.force,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_dto(report)


@router.post("/reanalyze")
async def reanalyze(body: AIAnalyzeRequest, principal: Principal = Depends(get_principal)):
    service = AIAnalysisService()
    try:
        report = await service.analyze(
            user_id=principal.user_id,
            threat_report_id=body.threat_report_id,
            channel=body.channel,
            triggered_by="user",
            force=True,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_dto(report)


@router.get("/report/{report_id}")
async def get_report(report_id: str, principal: Principal = Depends(get_principal)):
    db = get_db()
    report = await AIReportRepository(db).find_by_id(report_id)
    if not report or report.user_id != principal.user_id:
        raise HTTPException(status_code=404, detail="ai report not found")
    return _to_dto(report)


@router.get("/history")
async def history(
    page: int = 1,
    page_size: int = 25,
    verdict: str | None = None,
    principal: Principal = Depends(get_principal),
):
    db = get_db()
    if verdict:
        return await AIReportRepository(db).list_for_user(
            principal.user_id, page=page, page_size=page_size, verdict=verdict,
        )
    return await AIDecisionHistoryRepository(db).list_for_user(
        principal.user_id, page=page, page_size=page_size,
    )


@router.get("/models", response_model=list[AIModelInfo])
async def models(_: Principal = Depends(get_principal)):
    return [
        AIModelInfo(
            provider=config.default_model_provider,
            name=config.default_model_name,
            version=config.default_model_version,
            is_default=True,
            supports_json_mode=True,
            max_prompt_tokens=config.max_prompt_chars // 4,
        ),
    ]
