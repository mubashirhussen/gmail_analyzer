"""Exponential-backoff calculator and retry policy helpers.

Kept as a pure function so tasks and tests can reuse it without a Celery
context. Business tasks read `retry_delay_seconds(retry_count)` and pass
the result to `self.retry(countdown=...)`.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay_s: int = 15
    max_delay_s: int = 600
    jitter_ratio: float = 0.2   # ±20 %


DEFAULT_POLICY = RetryPolicy()


def retry_delay_seconds(retry_count: int, policy: RetryPolicy = DEFAULT_POLICY) -> int:
    """Exponential backoff with jitter. `retry_count` is 0-indexed."""
    exp = min(policy.max_delay_s, policy.base_delay_s * (2 ** max(0, retry_count)))
    jitter = exp * policy.jitter_ratio
    lo = max(1, int(exp - jitter))
    hi = int(exp + jitter)
    return random.randint(lo, hi)


def should_dead_letter(retry_count: int, policy: RetryPolicy = DEFAULT_POLICY) -> bool:
    return retry_count >= policy.max_retries
