from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/devices", tags=["devices"])


class RegisterIn(BaseModel):
    fingerprint: str
    label: str
    os: str
    browser: str
    session_token: str


@router.post("/register")
async def register(body: RegisterIn, user=Depends(require_user), db=Depends(get_db)):
    now = datetime.now(timezone.utc)
    await db.devices.update_one(
        {"user_id": user["sub"], "fingerprint": body.fingerprint},
        {"$setOnInsert": {"first_seen": now, "trusted": True},
         "$set": {"label": body.label, "os": body.os, "browser": body.browser, "last_seen": now}},
        upsert=True,
    )
    await db.sessions.update_one(
        {"session_token": body.session_token},
        {"$setOnInsert": {"created_at": now}, "$set": {"user_id": user["sub"], "last_active": now}},
        upsert=True,
    )
    return {"ok": True}


@router.get("")
async def list_devices(user=Depends(require_user), db=Depends(get_db)):
    return [{**d, "_id": str(d["_id"])} async for d in db.devices.find({"user_id": user["sub"]})]


@router.post("/{device_id}/logout")
async def logout(device_id: str, user=Depends(require_user), db=Depends(get_db)):
    await db.sessions.update_many(
        {"user_id": user["sub"], "device_id": device_id, "revoked_at": None},
        {"$set": {"revoked_at": datetime.now(timezone.utc)}},
    )
    return {"ok": True}
