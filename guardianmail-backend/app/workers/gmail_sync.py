"""Celery tasks for Gmail synchronisation.

Thin wrappers over ``GmailSyncService`` so each user's sync is isolated and
retryable. Business logic never lives in the task body.
"""
from __future__ import annotations

import asyncio

from celery.exceptions import MaxRetriesExceededError

from app.database.mongodb import mongodb
from app.database.redis import redis_client
from app.services.gmail.sync_service import gmail_sync_service
from app.workers.celery_app import celery


async def _bootstrap() -> None:
    if mongodb.db is None:
        await mongodb.connect()
    if redis_client.r is None:
        await redis_client.connect()


@celery.task(name="gmail.sync_all")
def sync_all() -> dict:
    """Fan out an incremental sync task per active Gmail connection."""

    async def run() -> dict:
        await _bootstrap()
        from app.database.mongodb import get_db
        from app.repositories.gmail_connections import GmailConnectionsRepository
        conns = await GmailConnectionsRepository(get_db()).all_active(limit=10_000)
        for c in conns:
            celery.send_task("gmail.sync_user", args=[c.user_id, "scheduled"])
        return {"enqueued": len(conns)}

    return asyncio.run(run())


@celery.task(name="gmail.sync_user", bind=True, max_retries=3, default_retry_delay=60,
             autoretry_for=(), acks_late=True)
def sync_user_task(self, user_id: str, kind: str = "scheduled") -> dict:
    async def run() -> dict:
        await _bootstrap()
        return await gmail_sync_service.sync_user(user_id, kind=kind)  # type: ignore[arg-type]

    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError:
            return {"user_id": user_id, "status": "failed", "error": str(exc)}


@celery.task(name="gmail.sync_labels", bind=True, max_retries=2, default_retry_delay=120)
def sync_labels_task(self, user_id: str) -> dict:
    async def run() -> dict:
        await _bootstrap()
        from app.database.mongodb import get_db
        from app.repositories.gmail_connections import GmailConnectionsRepository
        from app.services.gmail.label_service import label_service

        conn = await GmailConnectionsRepository(get_db()).get_active_for_user(user_id)
        if not conn:
            return {"user_id": user_id, "status": "no_connection"}
        n = await label_service.sync(user_id=user_id, refresh_token_enc=conn.refresh_token_enc)
        return {"user_id": user_id, "status": "success", "labels": n}

    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError:
            return {"user_id": user_id, "status": "failed", "error": str(exc)}
