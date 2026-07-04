from fastapi import APIRouter, Depends

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
async def dashboard(user=Depends(require_user), db=Depends(get_db)):
    uid = user["sub"]
    scanned = await db.emails.count_documents({"user_id": uid})
    threats = await db.threats.count_documents({"user_id": uid, "verdict": {"$ne": "safe"}})
    devices = await db.devices.count_documents({"user_id": uid})
    return {
        "scanned": scanned,
        "threats": threats,
        "devices": devices,
        "protection_score": max(0, 100 - int((threats / max(scanned, 1)) * 70)),
    }
