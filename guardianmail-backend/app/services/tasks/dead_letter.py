"""Dead-letter queue helpers.

When a task exhausts retries the failure envelope is:
  1. persisted on the originating `BackgroundJob` row (status=failed), and
  2. published to a Redis stream (`tasks:dlq`) so ops can page or a
     replay worker can re-enqueue after a fix.

This module owns only the DLQ *publication*. Replaying is a maintenance
task in `app/workers/maintenance_tasks.py`.
"""
from __future__ import annotations

import json
from typing import Any

from app.core.logging import get_logger
from app.database.redis import redis_client
from app.services.tasks.redis_keys import dead_letter_stream

_log = get_logger(__name__)
_MAX_LEN = 10_000  # capped stream — DLQ isn't durable history


async def publish(
    *,
    task_name: str,
    task_id: str,
    queue: str,
    args: list[Any] | None,
    kwargs: dict[str, Any] | None,
    error: str,
    retry_count: int,
) -> None:
    r = redis_client.client
    if r is None:
        _log.warning("dlq_publish_no_redis", task=task_name)
        return
    payload = {
        "task": task_name,
        "task_id": task_id,
        "queue": queue,
        "args": json.dumps(args or [], default=str)[:4000],
        "kwargs": json.dumps(kwargs or {}, default=str)[:4000],
        "error": error[:2000],
        "retry_count": str(retry_count),
    }
    try:
        await r.xadd(dead_letter_stream(), payload, maxlen=_MAX_LEN, approximate=True)
    except Exception as e:  # pragma: no cover
        _log.warning("dlq_publish_failed", error=str(e))


async def peek(count: int = 50) -> list[dict[str, Any]]:
    r = redis_client.client
    if r is None:
        return []
    entries = await r.xrevrange(dead_letter_stream(), count=count)
    out: list[dict[str, Any]] = []
    for stream_id, fields in entries:
        out.append({
            "id": stream_id.decode() if isinstance(stream_id, bytes) else stream_id,
            **{
                (k.decode() if isinstance(k, bytes) else k):
                (v.decode() if isinstance(v, bytes) else v)
                for k, v in fields.items()
            },
        })
    return out


async def size() -> int:
    r = redis_client.client
    if r is None:
        return 0
    try:
        return int(await r.xlen(dead_letter_stream()))
    except Exception:  # pragma: no cover
        return 0
