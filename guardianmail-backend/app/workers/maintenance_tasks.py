"""Maintenance queue tasks — cleanup, sweeps, and DLQ replay.

These live on the `maintenance` queue and are usually driven by Beat.
Each task is idempotent so a duplicate schedule tick is safe.
"""
from __future__ import annotations

import asyncio

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.database.redis import redis_client
from app.services.tasks import dead_letter
from app.services.tasks.priority import ALL_QUEUES
from app.workers.celery_app import celery

_log = get_logger(__name__)


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="maintenance.snapshot_queue_depth")
def snapshot_queue_depth() -> dict:
    """Poll broker queue depth and mirror it into the Prom gauge + Redis."""
    from app.core.metrics import QUEUE_DEPTH

    async def run() -> dict:
        r = redis_client.client
        depths: dict[str, int] = {}
        if r is None:
            return depths
        for q in ALL_QUEUES:
            try:
                depth = int(await r.llen(q))
            except Exception:
                depth = -1
            depths[q] = depth
            QUEUE_DEPTH.labels(queue=q).set(depth)
        return depths
    return asyncio.run(run())


@celery.task(name="maintenance.cleanup_background_jobs")
def cleanup_background_jobs(older_than_days: int = 60) -> dict:
    """Remove finished job rows past the TTL horizon.

    The `finished_at` TTL index handles this in prod, but explicit cleanup
    keeps development environments tidy and shortens Mongo compaction.
    """
    async def run() -> dict:
        await _bootstrap()
        cutoff = now_utc().replace(microsecond=0)
        res = await mongodb.db.background_jobs.delete_many({
            "status": {"$in": ["success", "cancelled"]},
            "finished_at": {"$lt": cutoff.replace(day=max(1, cutoff.day - older_than_days))},
        })
        return {"deleted": res.deleted_count}
    return asyncio.run(run())


@celery.task(name="maintenance.dlq_size")
def dlq_size() -> dict:
    from app.core.metrics import DEAD_LETTER_SIZE

    async def run() -> dict:
        size = await dead_letter.size()
        DEAD_LETTER_SIZE.set(size)
        return {"size": size}
    return asyncio.run(run())


@celery.task(name="maintenance.replay_dead_letter", bind=True)
def replay_dead_letter(self, limit: int = 50) -> dict:
    """Drain up to `limit` DLQ entries and re-dispatch them.

    Only replays task names in a small allow-list to avoid re-running
    poison messages that the maintainer hasn't triaged yet.
    """
    allowed = {
        "gmail.sync_user", "threat.rescan", "ocr.process_upload",
        "notifications.send", "analytics.recalculate",
    }

    async def run() -> dict:
        entries = await dead_letter.peek(count=limit)
        replayed = 0
        for entry in entries:
            name = entry.get("task", "")
            if name not in allowed:
                continue
            try:
                import json as _j
                args = _j.loads(entry.get("args") or "[]")
                kwargs = _j.loads(entry.get("kwargs") or "{}")
            except Exception:
                continue
            try:
                celery.send_task(name, args=args, kwargs=kwargs)
                replayed += 1
            except Exception as e:  # pragma: no cover
                _log.warning("dlq_replay_send_failed", task=name, error=str(e))
        return {"peeked": len(entries), "replayed": replayed}
    return asyncio.run(run())
