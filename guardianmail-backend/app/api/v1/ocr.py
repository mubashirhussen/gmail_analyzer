"""OCR & Attachment Security REST API.

All endpoints require an authenticated `Principal` — we never accept
anonymous uploads. Long-running work is delegated to Celery via
`ocr.process_upload`, but the report row is always created synchronously
so the client immediately gets a stable id to poll.
"""
from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.api.dependencies import Principal, get_principal
from app.database.mongodb import get_db
from app.repositories.ocr_reports import OCRReportRepository
from app.schemas.base import Page
from app.schemas.ocr import (
    OCRAnalyzeRequest, OCRJobAccepted, OCRReportDetail, OCRReportSummary,
    OCRUploadRequest,
)
from app.services.ocr.ocr_pipeline import OCRPipeline, summarise
from app.services.ocr.validation import OCRValidationError, validate_upload

router = APIRouter(prefix="/ocr", tags=["ocr"])


def _to_detail(r) -> OCRReportDetail:
    d = r.model_dump()
    return OCRReportDetail(
        id=r.id,
        user_id=r.user_id,
        status=r.status,
        source=r.source,
        extracted_text=r.extracted_text,
        text_truncated=r.text_truncated,
        ocr_confidence=r.ocr_confidence,
        processing_time_ms=r.processing_time_ms,
        page_count=r.page_count,
        engines_used=r.engines_used,
        patterns=d.get("patterns", {}),
        qr_results=d.get("qr_results", []),
        sensitive=d.get("sensitive", {}),
        security_indicators=d.get("security_indicators", {}),
        metadata=d.get("metadata", {}),
        attachment=d.get("attachment", {}),
        threat_report_id=r.threat_report_id,
        ai_report_id=r.ai_report_id,
        error_code=r.error_code,
        error_message=r.error_message,
        created_at=r.created_at,
        completed_at=r.completed_at,
    )


# ------------------------------------------------------------------- upload
@router.post("/upload", response_model=OCRReportSummary)
async def upload_json(
    body: OCRUploadRequest,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> OCRReportSummary:
    try:
        raw = base64.b64decode(body.data_b64, validate=True)
    except Exception as e:
        raise HTTPException(400, f"invalid base64: {e}") from e
    return await _process(db, principal, body.filename, body.mime_type, raw,
                          body.source, body.email_id,
                          body.forward_to_threat_intel, body.forward_to_ai)


@router.post("/upload/multipart", response_model=OCRReportSummary)
async def upload_multipart(
    file: UploadFile = File(...),
    source: str = Form("upload"),
    email_id: str | None = Form(None),
    forward_to_threat_intel: bool = Form(True),
    forward_to_ai: bool = Form(False),
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> OCRReportSummary:
    raw = await file.read()
    return await _process(
        db, principal, file.filename or "attachment",
        file.content_type or "application/octet-stream", raw,
        source, email_id, forward_to_threat_intel, forward_to_ai,
    )


async def _process(
    db, principal: Principal, filename: str, mime_type: str, raw: bytes,
    source: str, email_id: str | None,
    forward_threat: bool, forward_ai: bool,
) -> OCRReportSummary:
    # Validate up front so 4xx surfaces before we spin up the pipeline
    try:
        validate_upload(filename, mime_type, len(raw))
    except OCRValidationError as e:
        raise HTTPException(e.status_code, e.message) from e

    pipeline = OCRPipeline(db)
    report = await pipeline.run(
        user_id=principal.user_id, filename=filename,
        mime_type=mime_type, data=raw, source=source, email_id=email_id,
    )
    if forward_threat:
        await pipeline.forward_to_threat_intel(report)
    if forward_ai:
        await pipeline.forward_to_ai(report)
    return OCRReportSummary(**summarise(report))


# --------------------------------------------------------------- re-analyze
@router.post("/analyze", response_model=OCRJobAccepted)
async def reanalyze(
    body: OCRAnalyzeRequest,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> OCRJobAccepted:
    repo = OCRReportRepository(db)
    report = await repo.find_by_id(body.report_id)
    if not report or report.user_id != principal.user_id:
        raise HTTPException(404, "report not found")
    pipeline = OCRPipeline(db)
    tid = None
    if body.forward_to_threat_intel:
        tid = await pipeline.forward_to_threat_intel(report)
    if body.forward_to_ai:
        await pipeline.forward_to_ai(report)
    return OCRJobAccepted(report_id=report.id, status="dispatched", async_task_id=tid)


# ---------------------------------------------------------------- read API
@router.get("/report/{report_id}", response_model=OCRReportDetail)
async def get_report(
    report_id: str,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> OCRReportDetail:
    r = await OCRReportRepository(db).find_by_id(report_id)
    if not r or r.user_id != principal.user_id:
        raise HTTPException(404, "report not found")
    return _to_detail(r)


@router.get("/history", response_model=Page[OCRReportSummary])
async def history(
    page: int = 1,
    page_size: int = 25,
    principal: Principal = Depends(get_principal),
    db=Depends(get_db),
) -> Page[OCRReportSummary]:
    p = await OCRReportRepository(db).list_for_user(
        principal.user_id, page=page, page_size=page_size,
    )
    return Page[OCRReportSummary](
        items=[OCRReportSummary(**summarise(r)) for r in p.items],
        total=p.total, page=p.page, page_size=p.page_size,
    )
