"""TaskDispatcherService — the single write path for enqueuing work.

Every callsite that would previously do `celery.send_task(...)` should
route through here. The dispatcher:

1. Resolves the queue (`priority.queue_for`) if the caller didn't specify.
2. Persists a `BackgroundJob` row so the API/UI can poll.
3. Enforces per-user rate limits and optional dedup keys.
4. Sends the Celery task with the correct broker priority.
5. Back-links the Celery `task_id` onto the job row.

Failures never raise to the caller unless dedup/rate limiting rejected —
Celery broker failures degrade to a `pending` job that the maintenance
worker can retry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.exceptions import ConflictError, RateLimitError
from app.core.logging import get_logger
from app.database.redis import redis_client
from app.models.background_job import BackgroundJob
from app.repositories.background_jobs import BackgroundJobRepository
from app.services.tasks.priority import TaskPriority, queue_for
from app.services.tasks.redis_keys import dispatch_dedup, user_rate
from app.workers.celery_app import celery

_log = get_logger(__name__)

USER_RATE_LIMIT_PER_MINUTE = 60
DEFAULT_DEDUP_TTL_S = 60


@dataclass(slots=True)
class DispatchResult:
    job_id: str
    task_id: str | None
    queue: str
    priority: int
    status: str


class TaskDispatcherService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.jobs = BackgroundJobRepository(db)

    # ---------------------------------------------------------------- API
    async def dispatch(
        self,
        *,
        task_name: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        user_id: str | None = None,
        queue: str | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        dedup_key: str | None = None,
        dedup_ttl_s: int = DEFAULT_DEDUP_TTL_S,
        max_retries: int = 3,
        eta: Any | None = None,
        countdown: int | None = None,
    ) -> DispatchResult:
        target_queue = queue or queue_for(task_name)

        await self._enforce_rate_limit(user_id)
        await self._enforce_dedup(task_name, dedup_key, dedup_ttl_s)

        job = BackgroundJob(
            job_type=task_name,
            user_id=user_id,
            queue=target_queue,
            status="queued",
            max_retries=max_retries,
            payload={"args": list(args or []), "kwargs": dict(kwargs or {})},
        )
        await self.jobs.insert(job)

        task_id: str | None = None
        try:
            async_result = celery.send_task(
                task_name,
                args=list(args or []),
                kwargs=dict(kwargs or {}),
                queue=target_queue,
                priority=int(priority),
                eta=eta,
                countdown=countdown,
                headers={"job_id": job.id},
                retry=False,
            )
            task_id = async_result.id
            await self.jobs.update(
                {"_id": job.id},
                {"$set": {"task_id": task_id}},
            )
        except Exception as e:
            _log.exception("task_dispatch_failed", task=task_name)
            await self.jobs.transition(job.id, "pending", error=str(e))

        _log.info(
            "task_dispatched",
            task=task_name, queue=target_queue,
            priority=int(priority), job_id=job.id, task_id=task_id,
        )
        return DispatchResult(
            job_id=job.id, task_id=task_id, queue=target_queue,
            priority=int(priority), status=job.status,
        )

    # -------------------------------------------------------------- cancel
    async def cancel(self, job_id: str, user_id: str | None = None) -> bool:
        job = await self.jobs.find_by_id(job_id)
        if not job:
            return False
        if user_id and job.user_id and job.user_id != user_id:
            return False
        if job.task_id:
            try:
                celery.control.revoke(job.task_id, terminate=False)
            except Exception as e:  # pragma: no cover
                _log.warning("task_revoke_failed", task_id=job.task_id, error=str(e))
        await self.jobs.transition(job_id, "cancelled")
        return True

    # ---------------------------------------------------------------- retry
    async def retry_job(self, job_id: str) -> DispatchResult | None:
        job = await self.jobs.find_by_id(job_id)
        if not job or job.status not in ("failed", "cancelled"):
            return None
        args = list(job.payload.get("args") or [])
        kwargs = dict(job.payload.get("kwargs") or {})
        await self.jobs.bump_retry(job_id)
        return await self.dispatch(
            task_name=job.job_type, args=args, kwargs=kwargs,
            user_id=job.user_id, queue=job.queue, max_retries=job.max_retries,
        )

    # -------------------------------------------------------------- helpers
    async def _enforce_rate_limit(self, user_id: str | None) -> None:
        if not user_id:
            return
        r = redis_client.client
        if r is None:
            return
        key = user_rate(user_id)
        try:
            count = await r.incr(key)
            if count == 1:
                await r.expire(key, 60)
            if count > USER_RATE_LIMIT_PER_MINUTE:
                raise RateLimitError("too many task submissions", code="task_rate_limited")
        except RateLimitError:
            raise
        except Exception as e:  # pragma: no cover
            _log.warning("rate_limit_probe_failed", error=str(e))

    async def _enforce_dedup(
        self, task_name: str, dedup_key: str | None, ttl_s: int,
    ) -> None:
        if not dedup_key:
            return
        r = redis_client.client
        if r is None:
            return
        key = dispatch_dedup(task_name, dedup_key)
        try:
            ok = await r.set(key, "1", nx=True, ex=ttl_s)
            if not ok:
                raise ConflictError("duplicate task in dedup window", code="task_duplicate")
        except ConflictError:
            raise
        except Exception as e:  # pragma: no cover
            _log.warning("dedup_probe_failed", error=str(e))
