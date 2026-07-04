from fastapi import APIRouter, Depends

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/emails", tags=["emails"])


@router.get("")
async def list_emails(limit: int = 50, user=Depends(require_user), db=Depends(get_db)):
    cur = db.emails.find({"user_id": user["sub"]}, sort=[("received_at", -1)], limit=min(limit, 200))
    return [{**d, "_id": str(d["_id"])} async for d in cur]
