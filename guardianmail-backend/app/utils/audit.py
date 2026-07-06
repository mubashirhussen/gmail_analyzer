"""Fire-and-forget audit log writer."""
from datetime import datetime, timezone
from typing import Any

from app.database.mongodb import get_db


async def audit(event: str, *, user_id: str | None = None,
                severity: str = "info", meta: dict[str, Any] | None = None) -> None:
    await get_db().audit_logs.insert_one({
        "user_id": user_id, "event": event, "severity": severity,
        "meta": meta or {}, "at": datetime.now(timezone.utc),
    })
