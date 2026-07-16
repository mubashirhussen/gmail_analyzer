"""Passcode API — set/verify/change/lock."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import CurrentUser, Principal
from app.schemas.passcode import PasscodeChangeIn, PasscodeIn, PasscodeStatus
from app.services.auth.jwt_service import jwt_service
from app.services.auth.passcode_service import passcode_service

router = APIRouter(prefix="/auth/passcode", tags=["auth"])


@router.get("", response_model=PasscodeStatus)
async def status(p: Principal = CurrentUser):
    return PasscodeStatus(**await passcode_service.status(p.user_id))


@router.post("")
async def set_passcode(body: PasscodeIn, p: Principal = CurrentUser):
    await passcode_service.set(p.user_id, body.passcode)
    return {"ok": True}


@router.put("")
async def change_passcode(body: PasscodeChangeIn, p: Principal = CurrentUser):
    await passcode_service.change(p.user_id, body.current, body.new)
    return {"ok": True}


@router.post("/verify")
async def verify_passcode(body: PasscodeIn, p: Principal = CurrentUser):
    await passcode_service.verify(p.user_id, body.passcode)
    return {"ok": True}


@router.post("/lock")
async def lock_now(p: Principal = CurrentUser):
    """Force an immediate access-token blacklist (client goes to lock screen)."""
    await jwt_service.blacklist(p.access_jti)
    return {"ok": True}
