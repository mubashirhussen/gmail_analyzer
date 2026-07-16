"""End-to-end OCR pipeline orchestrator.

Runs synchronously (invoked from either an API request or a Celery worker)
so the caller decides the execution mode. Fully deterministic — the same
bytes and mime always produce the same report body.

    validate → hash → dedup → text extract → patterns → sensitive
    → qr → security indicators → metadata → attachment analysis
    → persist → optional downstream fan-out (threat + AI)

Any exception is caught and recorded on the report; the pipeline never
raises to the caller unless validation itself fails.
"""
from __future__ import annotations

import time
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.models.attachment_record import AttachmentRecord
from app.models.ocr_report import OCRReport
from app.repositories.attachment_records import AttachmentRecordRepository
from app.repositories.ocr_reports import OCRReportRepository
from app.services.ocr import (
    attachment_analyzer, metadata_extractor, pattern_extractor,
    qr_scanner, security_indicator_service, sensitive_detector,
    text_extraction,
)
from app.services.ocr.config import (
    TEXT_STORE_LIMIT, TEXT_TRUNCATE_MARKER,
)
from app.services.ocr.validation import validate_upload

_log = get_logger(__name__)


class OCRPipeline:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.reports = OCRReportRepository(db)
        self.attachments = AttachmentRecordRepository(db)

    # --------------------------------------------------------------- public
    async def run(
        self,
        *,
        user_id: str,
        filename: str,
        mime_type: str,
        data: bytes,
        source: str = "upload",
        email_id: str | None = None,
    ) -> OCRReport:
        vu = validate_upload(filename, mime_type, len(data))

        # dedup — same user + same bytes returns the previous report
        digest = attachment_analyzer.analyze(data, vu).sha256
        existing = await self.reports.find_by_hash(user_id, digest)
        if existing and existing.status == "completed":
            _log.info("ocr_dedup_hit", user_id=user_id, sha256=digest)
            return existing

        report = OCRReport(
            user_id=user_id,
            email_id=email_id,
            source=source,  # type: ignore[arg-type]
            status="processing",
        )
        await self.reports.insert(report)

        t0 = time.perf_counter()
        try:
            attachment = attachment_analyzer.analyze(data, vu)
            report.attachment = attachment
            report.metadata = metadata_extractor.extract(
                vu.filename, vu.extension, vu.mime_type, vu.size_bytes, data,
            )

            text, conf, page_count, engines = text_extraction.extract(data, vu.mime_type)
            report.ocr_confidence = round(conf, 3)
            report.page_count = page_count or report.metadata.page_count
            report.engines_used = engines

            report.patterns = pattern_extractor.extract_patterns(text)
            report.sensitive = sensitive_detector.detect(text)
            report.qr_results = qr_scanner.scan(data, vu.mime_type)
            report.security_indicators = security_indicator_service.build(
                text, report.patterns, report.qr_results,
            )

            # bound stored text to protect Mongo doc size
            if text and len(text) > TEXT_STORE_LIMIT:
                report.extracted_text = text[:TEXT_STORE_LIMIT] + TEXT_TRUNCATE_MARKER
                report.text_truncated = True
            else:
                report.extracted_text = text

            report.mark_completed()
        except Exception as e:
            _log.exception("ocr_pipeline_failed", user_id=user_id, filename=vu.filename)
            report.mark_failed("ocr_pipeline_error", str(e))
        finally:
            report.processing_time_ms = int((time.perf_counter() - t0) * 1000)
            await self.reports.update(
                {"_id": report.id},
                {"$set": report.model_dump(by_alias=True, exclude={"id"})},
            )

        # attach identity record (best-effort, never blocks the report)
        try:
            await self.attachments.upsert(AttachmentRecord(
                sha256=report.attachment.sha256,
                filename=report.attachment.filename,
                extension=report.attachment.extension,
                mime_type=report.attachment.mime_type,
                size_bytes=report.attachment.size_bytes,
                source=source,  # type: ignore[arg-type]
                user_id=user_id,
                email_id=email_id,
                ocr_report_id=report.id,
                double_extension=report.attachment.double_extension,
                is_executable=report.attachment.is_executable,
                is_archive=report.attachment.is_archive,
                is_encrypted=report.attachment.is_encrypted,
                contains_macros=report.attachment.contains_macros,
                known_bad_hash=report.attachment.known_bad_hash,
                risk_flags=list(report.attachment.risk_flags),
                first_seen_at=now_utc(),
                last_seen_at=now_utc(),
            ))
        except Exception as e:  # pragma: no cover
            _log.warning("attachment_record_upsert_failed", error=str(e))

        return report

    # --------------------------------------------------------------- fan-out
    async def forward_to_threat_intel(self, report: OCRReport) -> str | None:
        """Fire-and-forget: enqueue a threat scan for the extracted URLs.

        The threat engine (Module 5) owns its own persistence — we only
        record the linkage on the OCR report so the frontend can navigate.
        """
        if report.status != "completed":
            return None
        urls = list(dict.fromkeys(
            report.patterns.urls
            + [q.payload for q in report.qr_results if q.is_url]
            + report.metadata.embedded_links
            + report.attachment.hyperlinks,
        ))[:50]
        if not urls:
            return None
        try:
            from app.workers.threat_tasks import scan_urls_task  # type: ignore
            task = scan_urls_task.delay(  # type: ignore[union-attr]
                user_id=report.user_id, urls=urls,
                ocr_report_id=report.id, email_id=report.email_id,
            )
            await self.reports.update(
                {"_id": report.id},
                {"$set": {"forwarded_to_threat_at": now_utc()}},
            )
            return getattr(task, "id", None)
        except Exception as e:  # pragma: no cover
            _log.warning("threat_forward_failed", error=str(e))
            return None

    async def forward_to_ai(self, report: OCRReport) -> str | None:
        if report.status != "completed":
            return None
        try:
            from app.workers.ai_tasks import analyze_ocr_report_task  # type: ignore
            task = analyze_ocr_report_task.delay(  # type: ignore[union-attr]
                user_id=report.user_id, ocr_report_id=report.id,
            )
            await self.reports.update(
                {"_id": report.id},
                {"$set": {"forwarded_to_ai_at": now_utc()}},
            )
            return getattr(task, "id", None)
        except Exception as e:  # pragma: no cover
            _log.warning("ai_forward_failed", error=str(e))
            return None


def summarise(report: OCRReport) -> dict[str, Any]:
    return {
        "id": report.id,
        "user_id": report.user_id,
        "filename": report.attachment.filename or report.metadata.filename,
        "status": report.status,
        "ocr_confidence": report.ocr_confidence,
        "page_count": report.page_count,
        "processing_time_ms": report.processing_time_ms,
        "detected_url_count": len(report.patterns.urls),
        "detected_qr_count": len(report.qr_results),
        "detected_sensitive_count": sum(report.sensitive.counts.values()),
        "risk_flag_count": len(report.attachment.risk_flags),
        "created_at": report.created_at,
        "completed_at": report.completed_at,
    }
