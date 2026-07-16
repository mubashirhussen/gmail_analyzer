"""Celery signal handlers — persist execution history + emit Prometheus.

Registered by importing this module in `celery_app.py`. Uses a per-process
in-memory `t0` map keyed by task id so we can compute wall-clock duration
even when Celery doesn't attach one to the finish signal.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from celery.signals import (
    task_failure, task_postrun, task_prerun, task_retry, task_revoked,
)

from app.core.logging import get_logger
from app.core.metrics import (
    TASK_DURATION, TASK_FAILED, TASK_RETRIED, TASK_STARTED, TASK_SUCCEEDED,
)
from app.database.mongodb import mongodb
from app.repositories.background_jobs import BackgroundJobRepository
from app.services.tasks import dead_letter
from app.services.tasks.priority import Q_DEFAULT

_log = get_logger(__name__)
_STARTS: dict[str, float] = {}


def _job_id_from(headers: dict | None) -> str | None:
    if not headers:
        return None
    return headers.get("job_id") or headers.get("Job-Id")


def _run_async(coro) -> None:
    """Bridge async persistence calls into Celery's sync signal thread."""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    try:
        asyncio.run(coro)
    except Exception as e:  # pragma: no cover
        _log.warning("celery_signal_persist_failed", error=str(e))


async def _bootstrap() -> None:
    if mongodb.db is None:
        await mongodb.connect()


# --------------------------------------------------------------- prerun -----
@task_prerun.connect
def _prerun(task_id: str = "", task=None, args=None, kwargs=None, **_):
    name = getattr(task, "name", "unknown")
    queue = getattr(getattr(task, "request", None), "delivery_info", {}).get("routing_key", Q_DEFAULT)
    _STARTS[task_id] = time.perf_counter()
    TASK_STARTED.labels(task=name, queue=queue).inc()
    _log.info("task_prerun", task=name, task_id=task_id, queue=queue)

    async def _persist() -> None:
        await _bootstrap()
        repo = BackgroundJobRepository(mongodb.db)
        job = await repo.find_one({"task_id": task_id})
        if job:
            await repo.transition(job.id, "running")

    _run_async(_persist())


# ------------------------------------------------------------- postrun ------
@task_postrun.connect
def _postrun(task_id: str = "", task=None, retval=None, state=None, **_):
    name = getattr(task, "name", "unknown")
    queue = getattr(getattr(task, "request", None), "delivery_info", {}).get("routing_key", Q_DEFAULT)
    t0 = _STARTS.pop(task_id, None)
    dur_s = (time.perf_counter() - t0) if t0 else 0.0
    TASK_DURATION.labels(task=name, queue=queue).observe(dur_s)

    if state == "SUCCESS":
        TASK_SUCCEEDED.labels(task=name, queue=queue).inc()
        _log.info("task_success", task=name, task_id=task_id, duration_ms=int(dur_s * 1000))

        async def _persist() -> None:
            await _bootstrap()
            repo = BackgroundJobRepository(mongodb.db)
            job = await repo.find_one({"task_id": task_id})
            if job:
                await repo.transition(
                    job.id, "success",
                    result={"value": _as_jsonable(retval)},
                    duration_ms=int(dur_s * 1000),
                )
        _run_async(_persist())


# ---------------------------------------------------------------- retry -----
@task_retry.connect
def _retry(request=None, reason=None, **_):
    name = getattr(request, "task", "unknown")
    task_id = getattr(request, "id", "")
    queue = (getattr(request, "delivery_info", None) or {}).get("routing_key", Q_DEFAULT)
    TASK_RETRIED.labels(task=name, queue=queue).inc()
    _log.warning("task_retry", task=name, task_id=task_id, reason=str(reason)[:500])

    async def _persist() -> None:
        await _bootstrap()
        repo = BackgroundJobRepository(mongodb.db)
        job = await repo.find_one({"task_id": task_id})
        if job:
            await repo.bump_retry(job.id)
    _run_async(_persist())


# --------------------------------------------------------------- failure ----
@task_failure.connect
def _failure(task_id: str = "", exception=None, traceback=None,
             einfo=None, sender=None, **_):
    name = getattr(sender, "name", "unknown")
    queue = getattr(getattr(sender, "request", None), "delivery_info", {}).get("routing_key", Q_DEFAULT)
    exc_type = type(exception).__name__ if exception else "Unknown"
    TASK_FAILED.labels(task=name, queue=queue, exception=exc_type).inc()
    _log.error("task_failure", task=name, task_id=task_id,
               exception=exc_type, error=str(exception)[:500])

    async def _persist() -> None:
        await _bootstrap()
        repo = BackgroundJobRepository(mongodb.db)
        job = await repo.find_one({"task_id": task_id})
        args = kwargs = None
        retry_count = 0
        if job:
            args = list(job.payload.get("args") or [])
            kwargs = dict(job.payload.get("kwargs") or {})
            retry_count = job.retry_count
            await repo.transition(job.id, "failed", error=f"{exc_type}: {exception}")
        await dead_letter.publish(
            task_name=name, task_id=task_id, queue=queue,
            args=args, kwargs=kwargs, error=f"{exc_type}: {exception}",
            retry_count=retry_count,
        )
    _run_async(_persist())


# -------------------------------------------------------------- revoked -----
@task_revoked.connect
def _revoked(request=None, terminated=False, expired=False, **_):
    name = getattr(request, "task", "unknown")
    task_id = getattr(request, "id", "")
    _log.warning("task_revoked", task=name, task_id=task_id,
                 terminated=terminated, expired=expired)

    async def _persist() -> None:
        await _bootstrap()
        repo = BackgroundJobRepository(mongodb.db)
        job = await repo.find_one({"task_id": task_id})
        if job and job.status not in ("success", "failed"):
            await repo.transition(job.id, "cancelled")
    _run_async(_persist())


def _as_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    try:
        return str(value)[:2000]
    except Exception:  # pragma: no cover
        return None
