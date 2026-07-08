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
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.analytics.create_index([("user_id", 1), ("at", -1)])
    await db.automation_rules.create_index([("user_id", 1), ("enabled", 1)])
    await db.artifact_stats.create_index("hash", unique=True)
    await db.artifact_stats.create_index([("kind", 1), ("last_seen", -1)])
    await db.artifact_events.create_index([("hash", 1), ("at", -1)])
    await db.artifact_events.create_index([("user_id", 1), ("at", -1)])
    await db.device_artifacts.create_index([("user_id", 1), ("device_fingerprint", 1), ("at", -1)])
    await db.security_events.create_index([("user_id", 1), ("created_at", -1)])
    await db.security_events.create_index([("kind", 1), ("severity", 1)])
    await db.webhook_deliveries.create_index([("user_id", 1), ("created_at", -1)])
    await db.webhook_deliveries.create_index([("status", 1), ("next_attempt_at", 1)])
    await db.threats.create_index([("review_status", 1), ("created_at", -1)])
    await db.threats.create_index([("risk_score", -1), ("created_at", -1)])


