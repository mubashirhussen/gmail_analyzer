"""Community scam-reporting counter (mirrors the frontend's Supabase table)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/community", tags=["community"])


class ReportIn(BaseModel):
    hash: str = Field(min_length=16, max_length=128)
    kind: str = Field(pattern="^(email|social|url)$")
    category: str | None = None
    verdict: str | None = None


@router.post("/report")
async def report(body: ReportIn, user=Depends(require_user), db=Depends(get_db)):
    uid = user["sub"]
    now = datetime.now(timezone.utc)
    doc = await db.community_reports.find_one_and_update(
        {"hash": body.hash, "reporters": {"$ne": uid}},
        {
            "$setOnInsert": {"first_reported_at": now, "kind": body.kind},
            "$set": {"last_reported_at": now, "category": body.category, "last_verdict": body.verdict},
            "$inc": {"report_count": 1},
            "$addToSet": {"reporters": uid},
        },
        upsert=True, return_document=True,
    )
    return {"report_count": doc["report_count"], "newly_reported": True}


class CountsIn(BaseModel):
    hashes: list[str]


@router.post("/counts")
async def counts(body: CountsIn, user=Depends(require_user), db=Depends(get_db)):
    cur = db.community_reports.find({"hash": {"$in": body.hashes}}, {"hash": 1, "report_count": 1})
    return {"counts": {d["hash"]: d["report_count"] async for d in cur}}
