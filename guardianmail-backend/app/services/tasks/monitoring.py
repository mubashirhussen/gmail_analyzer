"""Task/queue/worker monitoring — pure reads.

Uses `celery.control.inspect` (blocking) inside a thread executor so the
API stays async. Everything is best-effort: an unreachable worker returns
`{}` and the API surfaces that rather than raising.
"""
from __future__ import annotations

import asyncio
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.logging import get_logger
from app.database.redis import redis_client
from app.repositories.background_jobs import BackgroundJobRepository
from app.services.tasks import dead_letter
from app.services.tasks.priority import ALL_QUEUES
from app.workers.celery_app import celery

_log = get_logger(__name__)


def _inspect():
    return celery.control.inspect(timeout=2.0)


class MonitoringService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.jobs = BackgroundJobRepository(db)

    # ------------------------------------------------------------- overview
    async def platform_health(self) -> dict[str, Any]:
        redis_ok = await self._redis_ping()
        broker_ok = await asyncio.to_thread(self._broker_ping)
        return {
            "redis": redis_ok,
            "broker": broker_ok,
            "dead_letter_size": await dead_letter.size(),
        }

    async def queue_depths(self) -> dict[str, int]:
        r = redis_client.client
        if r is None:
            return {q: -1 for q in ALL_QUEUES}
        out: dict[str, int] = {}
        for q in ALL_QUEUES:
            try:
                out[q] = int(await r.llen(q))
            except Exception:
                out[q] = -1
        return out

    async def workers(self) -> dict[str, Any]:
        def _collect() -> dict[str, Any]:
            insp = _inspect()
            try:
                return {
                    "stats": insp.stats() or {},
                    "active": insp.active() or {},
                    "reserved": insp.reserved() or {},
                    "scheduled": insp.scheduled() or {},
                    "registered": insp.registered() or {},
                }
            except Exception as e:  # pragma: no cover
                _log.warning("inspect_failed", error=str(e))
                return {}
        return await asyncio.to_thread(_collect)

    # ------------------------------------------------------------- history
    async def job(self, job_id: str) -> dict[str, Any] | None:
        j = await self.jobs.find_by_id(job_id)
        return j.model_dump() if j else None

    async def history(
        self, *, user_id: str | None = None, status: str | None = None,
        page: int = 1, page_size: int = 25,
    ):
        if user_id:
            return await self.jobs.list_for_user(
                user_id, status=status, page=page, page_size=page_size,  # type: ignore[arg-type]
            )
        f: dict[str, Any] = {}
        if status:
            f["status"] = status
        return await self.jobs.paginate(
            f, page=page, page_size=page_size,
            sort=[("created_at", -1)],
        )

    # ------------------------------------------------------------- helpers
    async def _redis_ping(self) -> bool:
        r = redis_client.client
        if r is None:
            return False
        try:
            return bool(await r.ping())
        except Exception:  # pragma: no cover
            return False

    def _broker_ping(self) -> bool:
        try:
            return bool(_inspect().ping())
        except Exception:  # pragma: no cover
            return False
