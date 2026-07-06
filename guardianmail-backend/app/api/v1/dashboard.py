from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
async def dashboard(user=Depends(require_user), db=Depends(get_db)):
    uid = user["sub"]
    since = datetime.now(timezone.utc) - timedelta(days=30)
    scanned = await db.emails.count_documents({"user_id": uid})
    threats = await db.threats.count_documents({"user_id": uid, "verdict": {"$ne": "safe"}})
    devices = await db.devices.count_documents({"user_id": uid, "status": "active"})
    recent = [
        {**d, "_id": str(d["_id"])}
        async for d in db.threats.find(
            {"user_id": uid, "created_at": {"$gte": since}},
            sort=[("created_at", -1)], limit=10,
        )
    ]
    cats = [
        c async for c in db.threats.aggregate([
            {"$match": {"user_id": uid, "attack_category": {"$ne": None}}},
            {"$group": {"_id": "$attack_category", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}, {"$limit": 5},
        ])
    ]
    return {
        "scanned": scanned,
        "threats": threats,
        "devices": devices,
        "protection_score": max(0, 100 - int((threats / max(scanned, 1)) * 70)),
        "recent": recent,
        "top_categories": [{"category": c["_id"], "count": c["count"]} for c in cats],
    }
