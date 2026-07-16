"""Celery tasks for complaint scheduling reminders."""
from __future__ import annotations

import asyncio

from app.database.mongodb import mongodb
from app.services.complaints.service import due_reminders, mark_reminded
from app.services.notifications.sender import send as send_notification
from app.workers.celery_app import celery


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="complaints.sweep_reminders")
def sweep_reminders() -> dict:
    async def run():
        await _bootstrap()
        sent = 0
        for c in await due_reminders():
            await send_notification(
                user_id=c["user_id"],
                kind="complaint_reminder",
                title="Complaint ready to submit",
                body=f"Your scheduled complaint to {c['destination']} is due.",
                meta={"complaint_id": c["_id"]},
            )
            await mark_reminded(c["_id"])
            sent += 1
        return {"reminders_sent": sent}
    return asyncio.run(run())
