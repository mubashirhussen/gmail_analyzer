"""Redis client + health probe."""
from __future__ import annotations

import redis.asyncio as aioredis
import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)


class RedisWrapper:
    r: aioredis.Redis | None = None

    async def connect(self) -> None:
        self.r = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            health_check_interval=30,
        )
        await self.ping()
        log.info("redis_connected")

    async def close(self) -> None:
        if self.r:
            await self.r.aclose()
            log.info("redis_closed")

    async def ping(self) -> bool:
        try:
            assert self.r is not None
            return bool(await self.r.ping())
        except Exception as e:  # noqa: BLE001
            log.warning("redis_ping_failed", err=str(e))
            return False


redis_client = RedisWrapper()


def get_redis() -> aioredis.Redis:
    if redis_client.r is None:
        raise RuntimeError("redis not connected")
    return redis_client.r
