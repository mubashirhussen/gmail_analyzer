from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings


class MongoDB:
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None

    async def connect(self) -> None:
        self.client = AsyncIOMotorClient(settings.MONGO_URI, uuidRepresentation="standard")
        self.db = self.client[settings.MONGO_DB]

    async def close(self) -> None:
        if self.client:
            self.client.close()


mongodb = MongoDB()


def get_db() -> AsyncIOMotorDatabase:
    assert mongodb.db is not None, "mongo not connected"
    return mongodb.db
