"""MongoDB connection manager (Motor).

Handles pooled async connections, health probes, and graceful reconnect.
Repositories import `get_db()` — never touch the client directly.
"""
from __future__ import annotations

import structlog
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import PyMongoError

from app.core.config import settings

log = structlog.get_logger(__name__)


class MongoDB:
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None

    async def connect(self) -> None:
        self.client = AsyncIOMotorClient(
            settings.MONGO_URI,
            uuidRepresentation="standard",
            maxPoolSize=settings.MONGO_MAX_POOL_SIZE,
            minPoolSize=settings.MONGO_MIN_POOL_SIZE,
            serverSelectionTimeoutMS=settings.MONGO_SERVER_SELECTION_TIMEOUT_MS,
            connectTimeoutMS=settings.MONGO_CONNECT_TIMEOUT_MS,
            retryWrites=True,
            appname=settings.APP_NAME,
        )
        self.db = self.client[settings.MONGO_DB]
        await self.ping()
        log.info("mongo_connected", db=settings.MONGO_DB)

    async def close(self) -> None:
        if self.client:
            self.client.close()
            log.info("mongo_closed")

    async def ping(self) -> bool:
        try:
            assert self.client is not None
            await self.client.admin.command("ping")
            return True
        except (PyMongoError, AssertionError) as e:
            log.warning("mongo_ping_failed", err=str(e))
            return False


mongodb = MongoDB()


def get_db() -> AsyncIOMotorDatabase:
    if mongodb.db is None:
        raise RuntimeError("mongo not connected")
    return mongodb.db
