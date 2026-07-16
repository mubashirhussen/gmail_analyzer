"""Analytics queue tasks — periodic aggregations and score refreshes.

Business logic (score formulae, trend series) belongs to future modules.
This file only wires the schedulable entry points and the DB touchpoints
so Beat has something concrete to call in this module.
"""
from __future__ import annotations

import asyncio

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.workers.celery_app import celery

_log = get_logger(__name__)


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="analytics.recalculate", bind=True, max_retries=2)
def recalculate(self, user_id: str | None = None) -> dict:
    async def run() -> dict:
        await _bootstrap()
        # count-only placeholder — real aggregations land with the analytics module
        q = {"user_id": user_id} if user_id else {}
        total = await mongodb.db.threats.count_documents(q)
        return {"user_id": user_id, "threats_seen": total, "at": now_utc().isoformat()}
    return asyncio.run(run())


@celery.task(name="analytics.daily_rollup")
def daily_rollup() -> dict:
    async def run() -> dict:
        await _bootstrap()
        users = await mongodb.db.users.count_documents({"status": "active"})
        threats = await mongodb.db.threats.count_documents({})
        _log.info("analytics_daily_rollup", active_users=users, total_threats=threats)
        return {"active_users": users, "total_threats": threats}
    return asyncio.run(run())
