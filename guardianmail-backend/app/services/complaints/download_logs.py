"""Download-audit log for evidence packs (Module 9)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.database.mongodb import get_db


async def record(
    *, pack_id: str, user_id: str, fmt: str,
    ip: str | None = None, user_agent: str | None = None,
    size: int | None = None,
) -> None:
    db = get_db()
    await db.evidence_downloads.insert_one({
        "pack_id": pack_id,
        "user_id": user_id,
        "format": fmt,
        "ip": ip,
        "user_agent": user_agent,
        "size": size,
        "at": datetime.now(timezone.utc),
    })
    await db.evidence_packs.update_one(
        {"_id": pack_id},
        {"$inc": {"download_count": 1},
         "$set": {"last_accessed_at": datetime.now(timezone.utc)}},
    )


async def history(user_id: str, *, pack_id: str | None = None,
                  limit: int = 100) -> list[dict[str, Any]]:
    db = get_db()
    q: dict[str, Any] = {"user_id": user_id}
    if pack_id:
        q["pack_id"] = pack_id
    cur = db.evidence_downloads.find(q, sort=[("at", -1)], limit=limit)
    return [{**d, "_id": str(d["_id"])} async for d in cur]
