"""Notification queue tasks — thin wrappers around the notification repo.

Real transport (email/webpush) is owned by future modules; here we only
persist an in-app notification and log the intent. Structured so callers
can dispatch `notifications.send` today without changing tomorrow.
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.models.notification import Notification
from app.repositories.notifications import NotificationRepository
from app.workers.celery_app import celery

_log = get_logger(__name__)


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="notifications.send", bind=True, max_retries=3,
             autoretry_for=(Exception,), retry_backoff=True,
             retry_backoff_max=120, retry_jitter=True)
def send_notification(self, user_id: str, title: str, body: str,
                      severity: str = "info", data: dict[str, Any] | None = None) -> dict:
    async def run() -> dict:
        await _bootstrap()
        repo = NotificationRepository(mongodb.db)
        n = Notification(
            user_id=user_id, title=title, body=body,
            severity=severity, data=data or {},
        )
        await repo.insert(n)
        _log.info("notification_persisted", user_id=user_id, severity=severity)
        return {"notification_id": n.id}
    return asyncio.run(run())


@celery.task(name="notifications.broadcast", bind=True, max_retries=3)
def broadcast(self, user_ids: list[str], title: str, body: str,
              severity: str = "info", data: dict[str, Any] | None = None) -> dict:
    count = 0
    for uid in user_ids:
        send_notification.delay(uid, title, body, severity, data)
        count += 1
    return {"queued": count}
