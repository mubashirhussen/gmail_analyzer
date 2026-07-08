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
    # Fan out to real-time SSE subscribers
    try:
        from app.api.v1.stream import publish_event
        await publish_event(user_id, "notification",
                            {"id": str(res.inserted_id), "title": title,
                             "severity": severity, "meta": meta or {}})
    except Exception as e:  # noqa: BLE001
        log.warning("sse_publish_failed", err=str(e))
    return str(res.inserted_id)


async def notify_threat(user_id: str, verdict: str, risk_score: int, subject: str,
                        meta: dict | None = None) -> None:
    if verdict == "safe":
        return
    from app.api.v1.preferences import get_preferences, should_notify
    prefs = await get_preferences(user_id)
    if not should_notify(prefs, verdict, risk_score):
        return

    sev: Severity = "critical" if verdict in ("phishing", "fraud") else "warn"
    payload_meta = {"verdict": verdict, "risk_score": risk_score, **(meta or {})}

    if prefs["channels"].get("in_app", True):
        await notify(user_id,
                     title=f"{verdict.title()} detected",
                     body=f"'{subject[:80]}' scored {risk_score}/100 — review recommended.",
                     severity=sev, meta=payload_meta)

    if prefs["channels"].get("webhook") and prefs.get("webhook_url"):
        from app.services.webhooks.delivery import enqueue_delivery
        await enqueue_delivery(
            user_id=user_id,
            url=prefs["webhook_url"],
            secret=prefs.get("webhook_secret") or "",
            event="threat.detected",
            payload={"verdict": verdict, "risk_score": risk_score,
                     "subject": subject, **payload_meta},
        )

    if prefs["channels"].get("email") and prefs.get("email_to"):
        log.info("email_notify_stub", to=prefs["email_to"], verdict=verdict,
                 risk_score=risk_score, subject=subject[:80])
