"""Redis token-bucket rate limiter (per-key, sliding window)."""
from __future__ import annotations

import time

from app.database.redis import get_redis


async def check(key: str, *, limit: int, window_s: int) -> tuple[bool, int]:
    """Return (allowed, remaining). Uses a simple fixed-window counter."""
    r = get_redis()
    bucket = f"rl:{key}:{int(time.time() // window_s)}"
    n = await r.incr(bucket)
    if n == 1:
        await r.expire(bucket, window_s)
    remaining = max(0, limit - int(n))
    return int(n) <= limit, remaining
