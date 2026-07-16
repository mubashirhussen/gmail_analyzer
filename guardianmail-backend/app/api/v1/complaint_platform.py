"""Complaint Management & Digital Evidence Platform API (Module 9).

Mounted at `/api/v1/complaint-platform` and `/api/v1/evidence-platform` so
it lives alongside the existing legacy `complaints`/`evidence` routers
without disturbing them.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field

from app.core.security import require_user
from app.services.complaints import (
    download_logs, platform_service, reminder_service,
)
from app.services.complaints.template_registry import (
    COMPLAINT_CATEGORIES, COMPLAINT_DESTINATIONS, list_templates,
)
from app.services.evidence.exporters import SUPPORTED_FORMATS
from app.services.evidence.integrity import custody_trail


router = APIRouter(prefix="/complaint-platform", tags=["complaint-platform"])
evidence_router = APIRouter(prefix="/evidence-platform", tags=["evidence-platform"])
reminder_router = APIRouter(prefix="/complaint-reminders",
                            tags=["complaint-reminders"])


# --------------------------------------------------------------------------- #
# Schemas                                                                     #
# --------------------------------------------------------------------------- #
class Victim(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    phone: str | None = None


class GenerateComplaintIn(BaseModel):
    threat_id: str
    destination: str = Field(..., description="see /templates for allowed values")
    category: str = Field(..., description="see /templates for allowed values")
    locale: str = "en"
    evidence_pack_id: str | None = None
    include_body: bool = False
    victim: Victim | None = None
    recommended_action: str | None = None


class UpdateComplaintIn(BaseModel):
    subject: str | None = None
    body: str | None = None


class TransitionIn(BaseModel):
    status: Literal["draft", "reviewed", "ready", "exported", "archived", "cancelled"]
    note: str | None = None


class GenerateEvidenceIn(BaseModel):
    threat_id: str
    include_body: bool = False


class ReminderIn(BaseModel):
    complaint_id: str
    preset: Literal["tomorrow", "next_week", "custom"] = "tomorrow"
    when: datetime | None = None
    note: str | None = None


# --------------------------------------------------------------------------- #
# Complaints                                                                  #
# --------------------------------------------------------------------------- #
@router.get("/templates")
async def get_templates(_user=Depends(require_user)) -> dict[str, Any]:
    return {
        "destinations": list(COMPLAINT_DESTINATIONS),
        "categories": list(COMPLAINT_CATEGORIES),
        "templates": await list_templates(),
    }


@router.post("/complaints/generate")
async def generate_complaint(body: GenerateComplaintIn,
                             user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.generate_complaint(
            user_id=user["sub"],
            threat_id=body.threat_id,
            destination=body.destination,
            category=body.category,
            locale=body.locale,
            evidence_pack_id=body.evidence_pack_id,
            include_body=body.include_body,
            victim=body.victim.model_dump() if body.victim else None,
            recommended_action=body.recommended_action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/complaints/history")
async def complaint_history(
    user=Depends(require_user),
    status: str | None = Query(default=None),
    destination: str | None = Query(default=None),
    category: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    skip: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    return await platform_service.list_complaints(
        user["sub"], status=status, destination=destination,
        category=category, limit=limit, skip=skip,
    )


@router.get("/complaints/{complaint_id}")
async def get_complaint(complaint_id: str,
                        user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.get_complaint(user["sub"], complaint_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.patch("/complaints/{complaint_id}")
async def patch_complaint(complaint_id: str, body: UpdateComplaintIn,
                          user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.update_complaint(
            user["sub"], complaint_id,
            subject=body.subject, body=body.body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.patch("/complaints/{complaint_id}/status")
async def transition(complaint_id: str, body: TransitionIn,
                     user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.transition_complaint(
            user["sub"], complaint_id, body.status, body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/complaints/{complaint_id}", status_code=204)
async def cancel_complaint(complaint_id: str, user=Depends(require_user)):
    try:
        await platform_service.delete_complaint(user["sub"], complaint_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# --------------------------------------------------------------------------- #
# Evidence                                                                    #
# --------------------------------------------------------------------------- #
@evidence_router.post("/generate")
async def generate_evidence(body: GenerateEvidenceIn,
                            user=Depends(require_user)) -> dict[str, Any]:
    try:
        bundle = await platform_service.generate_evidence_pack(
            user_id=user["sub"], threat_id=body.threat_id,
            include_body=body.include_body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    envelope = bundle["integrity"]
    return {
        "pack_id": envelope["pack_id"],
        "sha256": envelope["sha256"],
        "signature": envelope["signature"],
        "created_at": envelope["created_at"],
        "summary": bundle["summary"],
    }


@evidence_router.get("/packs/{pack_id}")
async def get_pack(pack_id: str, user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.get_pack(user["sub"], pack_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@evidence_router.get("/packs/{pack_id}/verify")
async def verify_pack(pack_id: str, user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await platform_service.verify_pack(user["sub"], pack_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@evidence_router.get("/packs/{pack_id}/custody")
async def get_custody(pack_id: str, user=Depends(require_user)) -> list[dict[str, Any]]:
    # Ownership check.
    await platform_service.get_pack(user["sub"], pack_id)
    return await custody_trail(pack_id)


@evidence_router.get("/packs/{pack_id}/download")
async def download_pack(
    pack_id: str,
    request: Request,
    user=Depends(require_user),
    fmt: str = Query(default="zip", pattern="^(pdf|docx|json|zip|csv)$"),
) -> Response:
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail="unsupported format")
    try:
        data, mime, filename = await platform_service.export_pack(
            user_id=user["sub"], pack_id=pack_id, fmt=fmt,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(
        data, media_type=mime,
        headers={
            "content-disposition": f'attachment; filename="{filename}"',
            "x-pack-id": pack_id,
        },
    )


@evidence_router.post("/packs/{pack_id}/download-token")
async def issue_token(pack_id: str, fmt: str = Query(default="zip"),
                      user=Depends(require_user)) -> dict[str, Any]:
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail="unsupported format")
    await platform_service.get_pack(user["sub"], pack_id)
    return platform_service.issue_download_token(pack_id, fmt, user["sub"])


@evidence_router.get("/downloads/history")
async def download_history(
    user=Depends(require_user),
    pack_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return await download_logs.history(user["sub"], pack_id=pack_id, limit=limit)


# --------------------------------------------------------------------------- #
# Reminders                                                                   #
# --------------------------------------------------------------------------- #
@reminder_router.post("")
async def schedule_reminder(body: ReminderIn,
                            user=Depends(require_user)) -> dict[str, Any]:
    try:
        return await reminder_service.schedule(
            user_id=user["sub"], complaint_id=body.complaint_id,
            preset=body.preset, when=body.when, note=body.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@reminder_router.get("")
async def list_reminders(user=Depends(require_user),
                         limit: int = Query(default=100, ge=1, le=500)):
    return await reminder_service.list_for_user(user["sub"], limit=limit)


@reminder_router.delete("/{reminder_id}", status_code=204)
async def cancel_reminder(reminder_id: str, user=Depends(require_user)):
    try:
        await reminder_service.cancel(user["sub"], reminder_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
