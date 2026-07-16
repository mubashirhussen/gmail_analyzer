"""Redis-backed cache abstraction.

Kept intentionally small: a `CacheClient` wraps `redis.asyncio.Redis`
with typed helpers (JSON get/set with TTL, hash-set counters, distributed
locks). Repositories/services depend on this abstraction so cache
back-ends can be swapped for tests (`fakeredis`) without changing calls.

Namespacing is enforced through `KEY` builders — no ad-hoc key strings in
callers. See `app/services/auth/redis_keys.py` for the auth namespace and
extend the same pattern per module.
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from redis.asyncio import Redis

from app.core.clock import now_utc
from app.core.ids import uuid_str
from app.core.logging import get_logger

log = get_logger(__name__)


class CacheClient:
    """Thin, typed wrapper around Redis for application caching."""

    def __init__(self, redis: Redis, *, prefix: str = "gm") -> None:
        self._r = redis
        self._prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    # ---- primitive ops --------------------------------------------------
    async def get_json(self, key: str) -> Any | None:
        raw = await self._r.get(self._k(key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("cache_json_decode_failed", key=key)
            return None

    async def set_json(self, key: str, value: Any, *, ttl: int | None = None) -> None:
        payload = json.dumps(value, default=str, separators=(",", ":"))
        await self._r.set(self._k(key), payload, ex=ttl)

    async def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        return await self._r.delete(*(self._k(k) for k in keys))

    async def incr(self, key: str, *, ttl: int | None = None) -> int:
        pipe = self._r.pipeline()
        pipe.incr(self._k(key))
        if ttl:
            pipe.expire(self._k(key), ttl)
        res = await pipe.execute()
        return int(res[0])

    async def expire(self, key: str, ttl: int) -> None:
        await self._r.expire(self._k(key), ttl)

    # ---- distributed lock ----------------------------------------------
    @asynccontextmanager
    async def lock(self, key: str, *, ttl: int = 30) -> AsyncIterator[bool]:
        token = uuid_str()
        acquired = await self._r.set(self._k(f"lock:{key}"), token, nx=True, ex=ttl)
        try:
            yield bool(acquired)
        finally:
            if acquired:
                # release only if we still own it (best-effort — real prod
                # should use the classic Lua CAS; kept simple here)
                cur = await self._r.get(self._k(f"lock:{key}"))
                if cur and cur.decode() == token:
                    await self._r.delete(self._k(f"lock:{key}"))


# ---------------------------------------------------------------------------
# Key builders — one namespace per module. Keep short: Redis keys are hot.
# ---------------------------------------------------------------------------
class CacheKeys:
    @staticmethod
    def user(user_id: str) -> str:
        return f"user:{user_id}"

    @staticmethod
    def user_by_email(email: str) -> str:
        return f"user:email:{email.lower()}"

    @staticmethod
    def dashboard(user_id: str) -> str:
        return f"dash:{user_id}"

    @staticmethod
    def threat_score(email_id: str) -> str:
        return f"threat:score:{email_id}"

    @staticmethod
    def unread_notifications(user_id: str) -> str:
        return f"notif:unread:{user_id}"

    @staticmethod
    def session(session_id: str) -> str:
        return f"sess:{session_id}"

    @staticmethod
    def rate_limit(bucket: str, key: str) -> str:
        return f"rl:{bucket}:{key}"


# Default TTLs (seconds). Central so ops can tune without code changes.
class CacheTTL:
    USER = 5 * 60
    DASHBOARD = 60
    THREAT_SCORE = 15 * 60
    UNREAD_NOTIF = 30
    SESSION = 10 * 60
