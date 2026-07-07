"""Forward + user-impact counters.

Each analyzed artifact (email/link/QR) is normalized to a stable hash. We
count how many distinct users have submitted it and how many total forwards
we've seen. Frontend uses this to show "N users impacted, forwarded M times".
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.database.mongodb import get_db
from app.utils.hashing import artifact_hash


async def record_forward(*, kind: str, key: str, user_id: str,
                         verdict: str, risk_score: int) -> dict:
    """kind ∈ email|url|qr|social. key is the raw artifact (URL, sender+subject, decoded QR)."""
    h = artifact_hash(kind, key)
    db = get_db()
    now = datetime.now(timezone.utc)

    await db.artifact_events.insert_one({
        "hash": h, "kind": kind, "user_id": user_id,
        "verdict": verdict, "risk_score": risk_score, "at": now,
    })

    await db.artifact_stats.update_one(
        {"hash": h},
        {
            "$setOnInsert": {"hash": h, "kind": kind, "first_seen": now},
            "$set": {"last_seen": now, "last_verdict": verdict, "last_risk_score": risk_score},
            "$inc": {"forward_count": 1},
            "$addToSet": {"impacted_users": user_id},
        },
        upsert=True,
    )

    doc = await db.artifact_stats.find_one({"hash": h})
    impacted = len(doc.get("impacted_users", [])) if doc else 1
    return {
        "hash": h,
        "forward_count": doc.get("forward_count", 1) if doc else 1,
        "impacted_users": impacted,
        "first_seen": doc.get("first_seen") if doc else now,
        "last_verdict": doc.get("last_verdict") if doc else verdict,
    }


async def get_stats(kind: str, key: str) -> dict:
    h = artifact_hash(kind, key)
    doc = await get_db().artifact_stats.find_one({"hash": h}) or {}
    return {
        "hash": h,
        "forward_count": doc.get("forward_count", 0),
        "impacted_users": len(doc.get("impacted_users", [])),
        "first_seen": doc.get("first_seen"),
        "last_seen": doc.get("last_seen"),
        "last_verdict": doc.get("last_verdict"),
    }
