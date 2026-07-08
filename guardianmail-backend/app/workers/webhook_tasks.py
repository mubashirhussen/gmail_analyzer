"""Celery task that drives webhook delivery retries."""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery
from app.database.mongodb import mongodb
from app.services.webhooks.delivery import attempt_delivery


async def _run(delivery_id: str) -> None:
    if mongodb.db is None:
        await mongodb.connect()
    await attempt_delivery(delivery_id)


@celery.task(name="webhook.deliver", acks_late=True)
def deliver_webhook(delivery_id: str) -> None:
    asyncio.run(_run(delivery_id))
