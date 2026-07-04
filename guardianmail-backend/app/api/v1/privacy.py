from fastapi import APIRouter, Depends
from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/privacy", tags=["privacy"])


@router.get("/export")
async def export_all(user=Depends(require_user), db=Depends(get_db)):
    uid = user["sub"]
    async def dump(coll: str):
        return [{**d, "_id": str(d["_id"])} async for d in db[coll].find({"user_id": uid})]
    return {c: await dump(c) for c in ("emails", "threats", "devices", "sessions", "audit_logs")}


@router.post("/delete")
async def delete_all(user=Depends(require_user), db=Depends(get_db)):
    uid = user["sub"]
    for c in ("emails", "threats", "devices", "sessions", "reports", "audit_logs"):
        await db[c].delete_many({"user_id": uid})
    await db.users.delete_one({"_id": uid})
    return {"ok": True}
