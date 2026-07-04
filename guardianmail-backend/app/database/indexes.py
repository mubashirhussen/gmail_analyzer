from motor.motor_asyncio import AsyncIOMotorDatabase


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    await db.users.create_index("email", unique=True)
    await db.devices.create_index([("user_id", 1), ("fingerprint", 1)], unique=True)
    await db.sessions.create_index("session_token", unique=True)
    await db.sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.emails.create_index([("user_id", 1), ("received_at", -1)])
    await db.emails.create_index("gmail_id", unique=True, sparse=True)
    await db.threats.create_index([("user_id", 1), ("created_at", -1)])
    await db.reports.create_index([("user_id", 1), ("period", 1)])
    await db.audit_logs.create_index([("user_id", 1), ("at", -1)])
    await db.community_reports.create_index("hash", unique=True)
    await db.community_reports.create_index([("hash", 1), ("reporters", 1)])
