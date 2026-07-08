"""Admin review queue for triaged threat artifacts."""
from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/admin/review", tags=["admin"])


def _require_admin(user: dict) -> None:
    if not user.get("is_admin") and user.get("role") != "admin":
        raise HTTPException(403, "admin only")


class ReviewUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|investigating|resolved|false_positive)$")
    notes: str = Field("", max_length=8000)


@router.get("/queue")
async def queue(
    user=Depends(require_user),
    status: str = Query("open", pattern="^(open|investigating|resolved|false_positive|all)$"),
    min_risk: int = 50,
    limit: int = 50,
    db=Depends(get_db),
):
    _require_admin(user)
    q: dict = {"risk_score": {"$gte": min_risk}}
    if status != "all":
        q["review_status"] = status if status != "open" else {"$in": ["open", None]}
    cur = db.threats.find(q).sort("created_at", -1).limit(min(limit, 200))
    return {"items": [d async for d in cur]}


@router.post("/{threat_id}")
async def update_review(threat_id: str, body: ReviewUpdate, user=Depends(require_user), db=Depends(get_db)):
    _require_admin(user)
    try:
        oid = ObjectId(threat_id)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, "invalid id") from e
    entry = {
        "at": datetime.now(timezone.utc),
        "by": user["sub"],
        "status": body.status,
        "notes": body.notes,
    }
    res = await db.threats.update_one(
        {"_id": oid},
        {"$set": {"review_status": body.status,
                  "review_updated_at": entry["at"],
                  "review_updated_by": user["sub"]},
         "$push": {"review_history": entry}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "threat not found")
    return {"ok": True, "review_status": body.status}
