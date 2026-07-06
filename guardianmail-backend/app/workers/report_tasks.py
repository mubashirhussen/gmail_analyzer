"""Report generation + nightly analytics rollup."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.database.mongodb import mongodb
from app.services.reports.generator import generate
from app.workers.celery_app import celery


async def _boot():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="reports.build")
def build(user_id: str, fmt: str = "pdf") -> dict:
    async def run():
        await _boot()
        data, mime = await generate(user_id, fmt)
        # In production, upload `data` to object storage and return a signed URL.
        # For now, persist size + metadata so the frontend can poll status.
        doc = {"user_id": user_id, "period": "adhoc", "fmt": fmt,
               "generated_at": datetime.now(timezone.utc),
               "size_bytes": len(data), "mime": mime, "storage_url": None}
        res = await mongodb.db.reports.insert_one(doc)
        return {"report_id": str(res.inserted_id), "size": len(data), "mime": mime}
    return asyncio.run(run())


@celery.task(name="reports.nightly_rollup")
def nightly_rollup() -> dict:
    async def run():
        await _boot()
        db = mongodb.db
        assert db is not None
        since = datetime.now(timezone.utc) - timedelta(days=1)
        pipeline = [
            {"$match": {"created_at": {"$gte": since}}},
            {"$group": {
                "_id": "$user_id",
                "total": {"$sum": 1},
                "threats": {"$sum": {"$cond": [{"$ne": ["$verdict", "safe"]}, 1, 0]}},
                "phish": {"$sum": {"$cond": [{"$eq": ["$verdict", "phishing"]}, 1, 0]}},
                "fraud": {"$sum": {"$cond": [{"$eq": ["$verdict", "fraud"]}, 1, 0]}},
            }},
        ]
        now = datetime.now(timezone.utc); n = 0
        async for row in db.threats.aggregate(pipeline):
            total = row["total"] or 1
            threats = row["threats"]
            snap = {
                "user_id": row["_id"], "at": now,
                "threat_score": min(100, int(threats / total * 100)),
                "security_score": max(0, 100 - int(threats / total * 60)),
                "privacy_score": 90, "trust_score": 85,
                "counts": {"total": total, "threats": threats,
                           "phishing": row["phish"], "fraud": row["fraud"]},
            }
            await db.analytics.insert_one(snap); n += 1
        return {"snapshots": n}
    return asyncio.run(run())


@celery.task(name="reports.weekly_digest")
def weekly_digest() -> dict:
    async def run():
        await _boot()
        db = mongodb.db
        assert db is not None
        n = 0
        async for u in db.users.find({}, {"_id": 1}):
            celery.send_task("reports.build", args=[str(u["_id"]), "pdf"], queue="report")
            n += 1
        return {"queued": n}
    return asyncio.run(run())
