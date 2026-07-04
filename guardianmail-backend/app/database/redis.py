import redis.asyncio as aioredis

from app.core.config import settings


class RedisWrapper:
    r: aioredis.Redis | None = None

    async def connect(self) -> None:
        self.r = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)

    async def close(self) -> None:
        if self.r:
            await self.r.aclose()


redis_client = RedisWrapper()


def get_redis() -> aioredis.Redis:
    assert redis_client.r is not None, "redis not connected"
    return redis_client.r
