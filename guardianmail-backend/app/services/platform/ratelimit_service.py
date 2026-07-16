"""Redis-backed sliding-window rate limiter (Module 11).

Complements the SlowAPI in-process limiter with a distributed limiter that
works across worker processes. Policies are keyed by scope (user, ip,
endpoint) with configurable window + burst.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import structlog

from app.core.exceptions import RateLimitError
from app.database.redis import redis_client
from app.services.platform.metrics_service import metrics_service

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RateLimitPolicy:
    """Sliding-window rate limit policy."""
    scope: str                # e.g. "user", "ip", "endpoint"
    limit: int                # max requests per window
    window_s: int             # window size in seconds
    burst: int = 0            # extra allowance beyond limit
    prefix: str = "rl"        # redis key prefix

    def key(self, identifier: str) -> str:
        return f"{self.prefix}:{self.scope}:{identifier}:{self.window_s}"


class RateLimitService:
    """Sliding-window counter using Redis sorted sets.

    Falls back to allow-on-error to avoid producing false-positive 429s
    during a partial outage (metric is emitted for observability).
    """

    async def check(self, policy: RateLimitPolicy, identifier: str) -> tuple[bool, int, int]:
        allowed = True
        remaining = policy.limit + policy.burst
        reset_s = policy.window_s
        cli = redis_client.client if redis_client.client else None
        if cli is None:
            return True, remaining, reset_s

        now_ms = int(time.time() * 1000)
        window_ms = policy.window_s * 1000
        key = policy.key(identifier)
        try:
            pipe = cli.pipeline()
            pipe.zremrangebyscore(key, 0, now_ms - window_ms)
            pipe.zcard(key)
            pipe.zadd(key, {f"{now_ms}-{identifier}": now_ms})
            pipe.pexpire(key, window_ms + 1000)
            _, count, _, _ = await pipe.execute()
            cap = policy.limit + policy.burst
            allowed = int(count) < cap
            remaining = max(0, cap - int(count) - 1)
            reset_s = policy.window_s
            if not allowed:
                metrics_service.rate_limit_hits.labels(scope=policy.scope).inc()
        except Exception as exc:  # noqa: BLE001
            log.warning("ratelimit_fail_open", err=str(exc), scope=policy.scope)
            return True, remaining, reset_s
        return allowed, remaining, reset_s

    async def enforce(self, policy: RateLimitPolicy, identifier: str) -> None:
        allowed, remaining, reset_s = await self.check(policy, identifier)
        if not allowed:
            raise RateLimitError(
                "rate limit exceeded",
                details={"scope": policy.scope, "reset_s": reset_s, "remaining": remaining},
            )


rate_limit_service = RateLimitService()
