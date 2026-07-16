"""Threat Intelligence Engine — Celery tasks.

These are thin async→sync bridges over the engine service. Retry policy
lives on the decorator; business logic lives in the service.
"""
from __future__ import annotations

import asyncio

from celery import shared_task

from app.core.logging import get_logger
from app.services.threat.engine_service import threat_engine_service

log = get_logger(__name__)


def _run(coro):
    """Run an async coroutine from a sync Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            new = asyncio.new_event_loop()
            try:
                return new.run_until_complete(coro)
            finally:
                new.close()
    except RuntimeError:
        pass
    return asyncio.run(coro)


@shared_task(
    name="threat.scan_email",
    bind=True, autoretry_for=(Exception,),
    retry_backoff=True, retry_backoff_max=300, retry_jitter=True,
    max_retries=3, acks_late=True,
)
def scan_email_task(self, user_id: str, email_id: str, triggered_by: str = "auto_sync") -> str:
    log.info("threat_scan_task_start", user_id=user_id, email_id=email_id)
    report = _run(threat_engine_service.scan_email(
        user_id=user_id, email_id=email_id, triggered_by=triggered_by,
    ))
    return report.id


@shared_task(
    name="threat.scan_url",
    autoretry_for=(Exception,),
    retry_backoff=True, retry_backoff_max=300, max_retries=3, acks_late=True,
)
def scan_url_task(user_id: str, url: str, triggered_by: str = "user_action") -> str:
    report = _run(threat_engine_service.scan_url(
        user_id=user_id, url=url, triggered_by=triggered_by,
    ))
    return report.id


@shared_task(
    name="threat.recheck",
    autoretry_for=(Exception,),
    retry_backoff=True, max_retries=3, acks_late=True,
)
def recheck_task(user_id: str, report_id: str) -> str:
    report = _run(threat_engine_service.recheck(user_id=user_id, report_id=report_id))
    return report.id
