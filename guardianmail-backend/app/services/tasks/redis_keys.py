"""Redis key namespaces for the background-processing platform."""
from __future__ import annotations

NS = "tasks"


def user_rate(user_id: str) -> str:
    return f"{NS}:rate:{user_id}"


def dispatch_dedup(task_name: str, key: str) -> str:
    """Coalesces duplicate submissions (same task + logical key)."""
    return f"{NS}:dedup:{task_name}:{key}"


def worker_lock(name: str) -> str:
    """Distributed lock guarding a critical section across workers."""
    return f"{NS}:lock:{name}"


def queue_depth_cache(queue: str) -> str:
    return f"{NS}:depth:{queue}"


def dead_letter_stream() -> str:
    return f"{NS}:dlq"
