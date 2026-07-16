"""Session management API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.dependencies import CurrentUser, Principal
from app.database.mongodb import get_db
from app.repositories.sessions import SessionsRepository
from app.schemas.session import SessionOut
from app.services.auth.session_service import session_service

router = APIRouter(prefix="/auth/sessions", tags=["auth"])


@router.get("", response_model=list[SessionOut])
async def list_sessions(p: Principal = CurrentUser):
    rows = await SessionsRepository(get_db()).list_active(p.user_id)
    return [
        SessionOut(id=s.id, device_id=s.device_id, ip=s.ip,
                   user_agent=s.user_agent, issued_at=s.issued_at,
                   last_active_at=s.last_active_at, expires_at=s.expires_at,
                   status=s.status, is_current=(s.id == p.session_id))
        for s in rows
    ]


@router.delete("/{session_id}")
async def revoke_session(session_id: str, p: Principal = CurrentUser):
    repo = SessionsRepository(get_db())
    s = await repo.find_by_id(session_id)
    if not s or s.user_id != p.user_id:
        raise HTTPException(404, "session not found")
    await session_service.revoke(
        session_id, user_id=p.user_id, reason="user_revoke",
        access_jti=p.access_jti if session_id == p.session_id else None,
    )
    return {"ok": True}
