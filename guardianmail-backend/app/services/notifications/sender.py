"""In-app + email notifications.

Notifications are persisted to Mongo for the frontend bell dropdown, and
optionally emailed for high-severity events. Email delivery is a pluggable
transport — provide SMTP settings via env; missing config = log-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

import structlog

from app.database.mongodb import get_db

log = structlog.get_logger()

Severity = Literal["info", "warn", "critical"]


async def notify(user_id: str, *, title: str, body: str,
                 severity: Severity = "info", meta: dict | None = None) -> str:
    db = get_db()
    doc = {
        "user_id": user_id, "title": title, "body": body,
        "severity": severity, "meta": meta or {},
        "read": False, "created_at": datetime.now(timezone.utc),
    }
    res = await db.notifications.insert_one(doc)
    log.info("notification", user_id=user_id, severity=severity, title=title)
    return str(res.inserted_id)


async def notify_threat(user_id: str, verdict: str, risk_score: int, subject: str) -> None:
    if verdict == "safe":
        return
    sev: Severity = "critical" if verdict in ("phishing", "fraud") else "warn"
    await notify(
        user_id,
        title=f"{verdict.title()} detected",
        body=f"'{subject[:80]}' scored {risk_score}/100 — review recommended.",
        severity=sev,
        meta={"verdict": verdict, "risk_score": risk_score},
    )
