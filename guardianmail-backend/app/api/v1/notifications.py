from fastapi import APIRouter, Depends
from bson import ObjectId

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(limit: int = 50, user=Depends(require_user), db=Depends(get_db)):
    cur = db.notifications.find({"user_id": user["sub"]},
                                sort=[("created_at", -1)], limit=min(limit, 200))
    return [{**d, "_id": str(d["_id"])} async for d in cur]


@router.post("/{nid}/read")
async def mark_read(nid: str, user=Depends(require_user), db=Depends(get_db)):
    await db.notifications.update_one(
        {"_id": ObjectId(nid), "user_id": user["sub"]}, {"$set": {"read": True}},
    )
    return {"ok": True}
