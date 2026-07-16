"""Device management API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.dependencies import CurrentUser, Principal
from app.schemas.device import DeviceOut, DeviceRenameIn
from app.services.auth.device_service import device_service
from app.services.auth.session_service import session_service

router = APIRouter(prefix="/auth/devices", tags=["auth"])


@router.get("", response_model=list[DeviceOut])
async def list_devices(p: Principal = CurrentUser):
    rows = await device_service.list_for(p.user_id)
    return [
        DeviceOut(id=d.id, label=d.label, browser=d.browser, os=d.os,
                  device_type=d.device_type, ip=d.ip, location=d.location,
                  trusted=d.trusted, risk=d.risk,
                  first_seen_at=d.first_seen_at, last_seen_at=d.last_seen_at,
                  is_current=(d.id == p.device_id))
        for d in rows
    ]


@router.patch("/{device_id}")
async def rename_device(device_id: str, body: DeviceRenameIn, p: Principal = CurrentUser):
    await device_service.rename(p.user_id, device_id, body.label)
    return {"ok": True}


@router.patch("/{device_id}/trust")
async def trust_device(device_id: str, trusted: bool = True, p: Principal = CurrentUser):
    await device_service.set_trusted(p.user_id, device_id, trusted)
    return {"ok": True, "trusted": trusted}


@router.delete("/{device_id}")
async def remove_device(device_id: str, p: Principal = CurrentUser):
    if device_id == p.device_id:
        raise HTTPException(400, "cannot remove the current device")
    await device_service.remove(p.user_id, device_id)
    await session_service.revoke_device_sessions(p.user_id, device_id)
    return {"ok": True}
