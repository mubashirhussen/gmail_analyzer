"""Celery tasks for Gmail synchronisation.

Each user's sync is its own task so retries and failures are isolated. The
per-message analysis is enqueued as `threat.analyze_email` and processed by
`phishing_tasks.analyze_email`.
"""
from __future__ import annotations

import asyncio

from app.database.mongodb import mongodb
from app.services.gmail.sync import sync_user as _sync_user
from app.workers.celery_app import celery


async def _bootstrap_db():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="gmail.sync_all")
def sync_all() -> dict:
    """Enumerate every user with a linked Gmail account and fan out."""
    async def run():
        await _bootstrap_db()
        db = mongodb.db
        assert db is not None
        enqueued = 0
        async for u in db.users.find({"gmail_refresh_encrypted": {"$ne": None}}, {"_id": 1}):
            celery.send_task("gmail.sync_user", args=[str(u["_id"])])
            enqueued += 1
        return {"enqueued": enqueued}
    return asyncio.run(run())


@celery.task(name="gmail.sync_user", bind=True, max_retries=3, default_retry_delay=60)
def sync_user(self, user_id: str) -> dict:
    async def run():
        await _bootstrap_db()
        result = await _sync_user(user_id)
        for gid in result.get("new_ids", []):
            # per-message analysis (payload built in phishing task from stored doc)
            celery.send_task("threat.analyze_gmail_message", args=[user_id, gid], queue="threat")
        return result
    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)
