"""Celery tasks for Phase 17 — advanced threat & fraud detection.

Every task is a thin async wrapper around the correlation service so it
can be invoked from Beat, from other workers, or on demand from the API
without duplicating logic.
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.services.detection.correlation import threat_correlation_service
from app.workers.celery_app import celery

log = get_logger(__name__)


async def _ensure_db() -> None:
    if not getattr(mongodb, "_client", None):
        await mongodb.connect()


def _run(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:  # already-running loop (e.g. embedded test runner)
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


@celery.task(name="threat.detection.analyze_email",
             autoretry_for=(Exception,), retry_backoff=True,
             retry_kwargs={"max_retries": 3})
def analyze_email(user_id: str, email_id: str) -> dict[str, Any]:
    async def _job():
        await _ensure_db()
        return await threat_correlation_service.analyze(
            user_id=user_id, email_id=email_id,
        )
    result = _run(_job())
    log.info("detection.task.analyze_email",
             user_id=user_id, email_id=email_id,
             classification=result.get("classification"),
             risk_score=result.get("risk_score"))
    return {"_id": result.get("_id"), "risk_score": result.get("risk_score"),
            "classification": result.get("classification")}


@celery.task(name="threat.detection.analyze_payload",
             autoretry_for=(Exception,), retry_backoff=True,
             retry_kwargs={"max_retries": 3})
def analyze_payload(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    async def _job():
        await _ensure_db()
        return await threat_correlation_service.analyze(
            user_id=user_id, payload=payload,
        )
    result = _run(_job())
    return {"_id": result.get("_id"), "risk_score": result.get("risk_score"),
            "classification": result.get("classification")}
