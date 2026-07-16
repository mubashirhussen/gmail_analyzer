"""Email list / detail endpoints backed by the metadata store."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.emails import EmailRepository

router = APIRouter(prefix="/emails", tags=["emails"])


@router.get("")
async def list_emails(
    p: Principal = CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    label: str | None = Query(default=None),
    sender_domain: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
):
    repo = EmailRepository(get_db())
    result = await repo.list_for_user(
        p.user_id, since=since, label=label, sender_domain=sender_domain,
        page=page, page_size=page_size,
    )
    return {
        "items": [_summary(d) for d in result.items],
        "total": result.total, "page": result.page, "page_size": result.page_size,
    }


@router.get("/{email_id}")
async def get_email(email_id: str, p: Principal = CurrentUser):
    repo = EmailRepository(get_db())
    doc = await repo.find_by_id(email_id)
    if not doc or doc.user_id != p.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "email not found")
    return doc.model_dump(by_alias=True)


@router.get("/thread/{thread_id}")
async def get_thread(thread_id: str, p: Principal = CurrentUser):
    repo = EmailRepository(get_db())
    docs = await repo.list_thread(p.user_id, thread_id)
    return [_summary(d) for d in docs]


def _summary(d) -> dict:
    return {
        "id": d.id,
        "gmail_id": d.gmail_id,
        "thread_id": d.thread_id,
        "sender": d.sender,
        "sender_email": d.sender_email,
        "sender_domain": d.sender_domain,
        "subject": d.subject,
        "snippet": d.snippet,
        "labels": d.labels,
        "is_unread": d.is_unread,
        "is_starred": d.is_starred,
        "has_attachments": d.has_attachments,
        "url_count": len(d.urls),
        "attachment_count": len(d.attachments),
        "received_at": d.received_at,
        "analysis_status": d.analysis_status,
        "threat_id": d.threat_id,
    }
