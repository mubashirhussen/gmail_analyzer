"""Celery tasks for the AI Analysis Engine (Module 6).

Tasks are thin adapters: they resolve args, delegate to
`AIAnalysisService`, and rely on Celery's retry policy for transient
failures. Business logic never lives inside a task body.
"""
from __future__ import annotations

import asyncio

from celery import shared_task

from app.core.logging import get_logger
from app.services.ai.ai_analysis_service import AIAnalysisService

log = get_logger(__name__)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(name="ai.analyze", bind=True, max_retries=3, default_retry_delay=15)
def ai_analyze(self, user_id: str, threat_report_id: str,
               *, channel: str = "email", triggered_by: str = "auto",
               force: bool = False):
    try:
        service = AIAnalysisService()
        report = _run(service.analyze(
            user_id=user_id, threat_report_id=threat_report_id,
            channel=channel, triggered_by=triggered_by, force=force,
        ))
        return {"ai_report_id": report.id, "verdict": report.verdict,
                "confidence": report.confidence.overall}
    except Exception as exc:  # noqa: BLE001
        log.error("ai.analyze.failed", error=str(exc),
                  threat_report_id=threat_report_id)
        raise self.retry(exc=exc)


@shared_task(name="ai.reanalyze", bind=True, max_retries=2, default_retry_delay=30)
def ai_reanalyze(self, user_id: str, threat_report_id: str):
    return ai_analyze.apply(  # reuse main task, force cache bypass
        args=(user_id, threat_report_id),
        kwargs={"force": True, "triggered_by": "user"},
    ).get()
