"""Complaint drafting, scheduling, history and status transitions."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

from app.core.security import require_user
from app.services.complaints.service import (
    draft_from_threat, get_one, list_history, transition,
    VALID_STATUSES, VALID_DESTINATIONS,
)

router = APIRouter(prefix="/complaints", tags=["complaints"])


class Victim(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    phone: str | None = None


class DraftIn(BaseModel):
    threat_id: str
    destination: str = Field(pattern="^(cybercrime_gov_in|report_phishing)$")
    scheduled_for: datetime | None = None
    victim: Victim | None = None
    include_body: bool = False


class TransitionIn(BaseModel):
    status: str
    note: str | None = None


@router.post("/draft")
async def draft(body: DraftIn, user=Depends(require_user)):
    try:
        return await draft_from_threat(
            user_id=user["sub"], threat_id=body.threat_id,
            destination=body.destination, scheduled_for=body.scheduled_for,
            victim=body.victim.model_dump() if body.victim else None,
            include_body=body.include_body,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("")
async def history(
    user=Depends(require_user),
    status: str | None = Query(default=None),
    destination: str | None = Query(default=None),
    category: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
):
    if status and status not in VALID_STATUSES:
        raise HTTPException(400, "invalid status")
    if destination and destination not in VALID_DESTINATIONS:
        raise HTTPException(400, "invalid destination")
    return await list_history(user["sub"], status, destination, category, limit)


@router.get("/{complaint_id}")
async def one(complaint_id: str, user=Depends(require_user)):
    try:
        return await get_one(user["sub"], complaint_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.patch("/{complaint_id}/status")
async def set_status(complaint_id: str, body: TransitionIn, user=Depends(require_user)):
    try:
        return await transition(user["sub"], complaint_id, body.status, body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
