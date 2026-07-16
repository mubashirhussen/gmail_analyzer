"""Celery tasks for the OCR & Attachment Security engine.

Kept intentionally thin: each task delegates to `OCRPipeline` and re-uses
the same async DB connection bootstrap pattern the rest of the workers
follow. Tasks are idempotent by SHA-256 (`OCRPipeline.run` dedupes).
"""
from __future__ import annotations

import asyncio
import base64

from celery.exceptions import Retry

from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.services.ocr.ocr import extract_text  # legacy — kept for compatibility
from app.services.ocr.ocr_pipeline import OCRPipeline
from app.workers.celery_app import celery

_log = get_logger(__name__)


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


# ---------------------------------------------------------- legacy shim ----
@celery.task(name="ocr.extract")
def ocr_extract(data_b64: str, mime: str) -> str:
    """Legacy plain-text extraction task (kept for existing callers)."""
    return asyncio.run(extract_text(base64.b64decode(data_b64), mime))


# ---------------------------------------------------------- new pipeline ---
@celery.task(
    name="ocr.process_upload",
    bind=True, max_retries=3, default_retry_delay=15,
    autoretry_for=(Exception,), retry_backoff=True, retry_backoff_max=120,
    retry_jitter=True, acks_late=True,
)
def process_upload_task(
    self, user_id: str, filename: str, mime_type: str, data_b64: str,
    source: str = "upload", email_id: str | None = None,
    forward_threat: bool = True, forward_ai: bool = False,
) -> dict:
    async def run() -> dict:
        await _bootstrap()
        raw = base64.b64decode(data_b64)
        pipeline = OCRPipeline(mongodb.db)
        report = await pipeline.run(
            user_id=user_id, filename=filename, mime_type=mime_type,
            data=raw, source=source, email_id=email_id,
        )
        if forward_threat:
            await pipeline.forward_to_threat_intel(report)
        if forward_ai:
            await pipeline.forward_to_ai(report)
        return {"report_id": report.id, "status": report.status}

    try:
        return asyncio.run(run())
    except Retry:
        raise
    except Exception as e:
        _log.exception("ocr_process_upload_failed", user_id=user_id, filename=filename)
        raise self.retry(exc=e)


@celery.task(name="ocr.forward_to_threat", acks_late=True)
def forward_to_threat_task(report_id: str) -> dict:
    async def run() -> dict:
        await _bootstrap()
        pipeline = OCRPipeline(mongodb.db)
        report = await pipeline.reports.find_by_id(report_id)
        if not report:
            return {"status": "not_found"}
        tid = await pipeline.forward_to_threat_intel(report)
        return {"status": "dispatched", "task_id": tid}
    return asyncio.run(run())


@celery.task(name="ocr.forward_to_ai", acks_late=True)
def forward_to_ai_task(report_id: str) -> dict:
    async def run() -> dict:
        await _bootstrap()
        pipeline = OCRPipeline(mongodb.db)
        report = await pipeline.reports.find_by_id(report_id)
        if not report:
            return {"status": "not_found"}
        tid = await pipeline.forward_to_ai(report)
        return {"status": "dispatched", "task_id": tid}
    return asyncio.run(run())
