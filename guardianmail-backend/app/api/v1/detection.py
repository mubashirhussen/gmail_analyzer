"""Phase 17 — Advanced detection API surface."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.detection import (
    DetectionRepository,
    FraudIndicatorRepository,
)
from app.schemas.detection import AnalyzeRequest, DetectionOut
from app.services.detection.correlation import threat_correlation_service

router = APIRouter(prefix="/detection", tags=["detection"])


@router.post("/analyze", response_model=DetectionOut)
async def analyze(body: AnalyzeRequest, principal: Principal = CurrentUser):
    if not (body.email_id or body.threat_id or body.subject or body.body):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="analyze_requires_email_or_payload",
        )
    result = await threat_correlation_service.analyze(
        user_id=principal.user_id,
        email_id=body.email_id,
        threat_id=body.threat_id,
        payload={
            "subject": body.subject,
            "sender": body.sender,
            "body": body.body,
            "headers": body.headers,
            "urls": body.urls,
            "attachments": body.attachments,
        },
    )
    return result


@router.get("/history")
async def history(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    min_score: float | None = Query(None, ge=0, le=100),
):
    db = get_db()
    return await DetectionRepository(db).list_for_user(
        principal.user_id, page=page, page_size=page_size, min_score=min_score,
    )


@router.get("/{detection_id}", response_model=DetectionOut)
async def get_one(detection_id: str, principal: Principal = CurrentUser):
    db = get_db()
    doc = await DetectionRepository(db).find_by_id(detection_id)
    if not doc or doc.get("user_id") != principal.user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="detection_not_found")
    return doc


risk_router = APIRouter(prefix="/risk-score", tags=["detection"])


@risk_router.get("/{detection_id}")
async def risk_score(detection_id: str, principal: Principal = CurrentUser):
    db = get_db()
    doc = await DetectionRepository(db).find_by_id(detection_id)
    if not doc or doc.get("user_id") != principal.user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="detection_not_found")
    return {
        "detection_id": detection_id,
        "risk_score": doc.get("risk_score"),
        "confidence": doc.get("confidence"),
        "classification": doc.get("classification"),
        "attack_complexity": doc.get("attack_complexity"),
        "potential_impact": doc.get("potential_impact"),
    }


fraud_router = APIRouter(prefix="/fraud", tags=["detection"])


@fraud_router.get("/history")
async def fraud_history(
    principal: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    db = get_db()
    return await FraudIndicatorRepository(db).list_for_user(
        principal.user_id, page=page, page_size=page_size,
    )
