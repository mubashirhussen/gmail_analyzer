"""Report lifecycle orchestration + templated body assembly.

Flow
----
1. `create_pending()` inserts a `report_records` row in status=`pending`,
   optionally returning immediately for async workers to pick up.
2. `generate_now()` (or the Celery task) calls `_assemble()` to build the
   section list, delegates to `ExportService`, hashes the bytes, and
   updates the record to `ready` with size + checksum + download token.
3. `download()` looks the token up, streams bytes back (in this module we
   return the payload; production layers may switch to signed URLs).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.models.report_record import ReportRecord
from app.repositories.report_records import ReportRecordsRepository
from app.schemas.analytics_platform import (
    ReportGenerateRequest, ReportSummary, TimeRange,
)
from app.services.analytics_platform.analytics_service import AnalyticsService
from app.services.analytics_platform.export_service import ExportService
from app.services.analytics_platform.time_filters import TimeFilterService

_log = get_logger(__name__)

DOWNLOAD_TTL_HOURS = 24


class ReportingService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.repo = ReportRecordsRepository(db)
        self.analytics = AnalyticsService(db)
        self.export = ExportService()
        self.time = TimeFilterService()

    # ------------------------------------------------------------- pending
    async def create_pending(
        self, user_id: str, req: ReportGenerateRequest,
    ) -> ReportRecord:
        tr = self.time.resolve(req.time_filter, since=req.since, until=req.until)
        rec = ReportRecord(
            user_id=user_id, kind=req.kind, fmt=req.fmt, status="pending",
            period_start=tr.since, period_end=tr.until,
            filters={"time_filter": req.time_filter,
                     "include_sections": req.include_sections},
            requested_by=user_id, requested_at=now_utc(),
        )
        await self.repo.insert(rec)
        return rec

    # ------------------------------------------------------------- summary
    def _summary(self, rec: ReportRecord) -> ReportSummary:
        url = f"/api/v1/reports-platform/download/{rec.download_token}" \
            if rec.download_token else None
        return ReportSummary(
            id=rec.id, kind=rec.kind, fmt=rec.fmt, status=rec.status,
            generated_at=rec.generated_at, period_start=rec.period_start,
            period_end=rec.period_end, size_bytes=rec.size_bytes,
            download_url=url, expires_at=rec.expires_at,
        )

    async def list_for_user(self, user_id: str, kind: str | None = None) -> list[ReportSummary]:
        rows = await self.repo.list_for_user(user_id, kind=kind)
        return [self._summary(r) for r in rows]

    # ----------------------------------------------------------- generation
    async def generate_now(self, report_id: str) -> ReportRecord:
        rec = await self.repo.find_by_id(report_id)
        if not rec:
            raise LookupError(f"report {report_id} missing")
        await self.repo.set_status(report_id, "running")
        try:
            tr = self.time.resolve(
                rec.filters.get("time_filter", "last_30_days"),
                since=rec.period_start, until=rec.period_end,
            )
            title, sections = await self._assemble(rec.user_id, rec.kind, tr,
                                                    rec.filters.get("include_sections"))
            data, mime = self._serialize(rec.fmt, title, sections)
            checksum = hashlib.sha256(data).hexdigest()
            token = secrets.token_urlsafe(32)
            expires = now_utc() + timedelta(hours=DOWNLOAD_TTL_HOURS)
            # persist bytes reference — production stores in object storage.
            storage_url = await self._persist_bytes(rec.id, data, mime)
            extra = {
                "size_bytes": len(data), "mime": mime,
                "storage_url": storage_url, "checksum_sha256": checksum,
                "download_token": token, "generated_at": now_utc(),
                "expires_at": expires,
                "summary": {"sections": [s.get("title") for s in sections]},
            }
            await self.repo.set_status(report_id, "ready", extra=extra)
            _log.info("report_generated", report_id=report_id, size=len(data),
                      fmt=rec.fmt, kind=rec.kind)
            return await self.repo.get_by_id(report_id)
        except Exception as exc:  # noqa: BLE001
            _log.error("report_generation_failed", report_id=report_id, error=str(exc))
            await self.repo.set_status(report_id, "failed", error=str(exc))
            raise

    # ------------------------------------------------------------- download
    async def download(self, token: str) -> tuple[bytes, str, ReportRecord]:
        rec = await self.repo.by_download_token(token)
        if not rec or rec.status != "ready":
            raise LookupError("report unavailable")
        if rec.expires_at and rec.expires_at < now_utc():
            await self.repo.set_status(rec.id, "expired")
            raise LookupError("download link expired")
        data = await self._read_bytes(rec.id)
        await self.repo.mark_downloaded(rec.id)
        return data, rec.mime or "application/octet-stream", rec

    # -------------------------------------------------------------- assemble
    async def _assemble(
        self, user_id: str, kind: str, tr: TimeRange,
        include: list[str] | None,
    ) -> tuple[str, list[dict]]:
        email = await self.analytics.email_analytics(user_id, tr)
        threats = await self.analytics.threat_analytics(user_id, tr)
        security = await self.analytics.security_analytics(user_id, tr)
        base_sections: list[dict] = [
            {"title": "Executive summary", "body":
                f"Between {tr.since:%Y-%m-%d} and {tr.until:%Y-%m-%d}, "
                f"GuardianMail scanned {email.total} emails and detected "
                f"{threats.total} threats. Security score: "
                f"{security.security_score.score}/100."},
            {"title": "Email activity", "body": [{
                "metric": k, "value": v} for k, v in email.model_dump().items()]},
            {"title": "Threat highlights", "body":
                threats.dangerous_domains[:15] or [{"note": "no dangerous domains"}]},
            {"title": "Top sender risks", "body":
                threats.top_sender_risks[:15] or [{"note": "no risky senders"}]},
        ]
        if kind == "threat":
            sections = base_sections[2:] + [
                {"title": "Repeated attackers", "body": threats.repeated_attackers[:20] or [{}]},
            ]
        elif kind == "security":
            sections = [
                base_sections[0],
                {"title": "Security scores", "body": [
                    security.security_score.model_dump(),
                    security.trust_score.model_dump(),
                    security.threat_score.model_dump(),
                ]},
                {"title": "Threat highlights", "body":
                    threats.dangerous_domains[:15] or [{}]},
            ]
        elif kind == "email_activity":
            sections = [base_sections[0], base_sections[1]]
        elif kind == "executive":
            sections = base_sections
        elif kind in ("daily", "weekly", "monthly"):
            sections = base_sections
        elif kind == "analytics_snapshot":
            sections = [
                {"title": "Snapshot", "body": [{
                    "period": f"{tr.since:%Y-%m-%d} to {tr.until:%Y-%m-%d}",
                    "emails": email.total,
                    "threats": threats.total,
                    "security_score": security.security_score.score,
                    "protection_pct": security.protection_pct,
                }]},
            ]
        else:
            sections = base_sections

        if include:
            sections = [s for s in sections if s.get("title") in include] or sections
        return f"GuardianMail — {kind.replace('_', ' ').title()} report", sections

    def _serialize(self, fmt: str, title: str, sections: list[dict]) -> tuple[bytes, str]:
        if fmt == "pdf":
            return self.export.to_pdf(title, sections)
        if fmt == "docx":
            return self.export.to_docx(title, sections)
        if fmt == "xlsx":
            sheets: dict[str, list[dict]] = {}
            for s in sections:
                body = s.get("body")
                sheets[s.get("title", "sheet")] = body if isinstance(body, list) else [{"body": str(body)}]
            return self.export.to_xlsx(sheets)
        if fmt == "csv":
            rows: list[dict] = []
            for s in sections:
                body = s.get("body")
                if isinstance(body, list):
                    for r in body:
                        rows.append({"section": s.get("title"), **(r if isinstance(r, dict) else {"value": r})})
                else:
                    rows.append({"section": s.get("title"), "value": str(body)})
            return self.export.to_csv(rows)
        return self.export.to_json({"title": title, "sections": sections})

    # ------------------------------------------------------------ bytes I/O
    async def _persist_bytes(self, report_id: str, data: bytes, mime: str) -> str:
        # Store report bytes in GridFS for portability. Production may swap
        # to signed object-storage URLs; the persistence layer is the only
        # place that needs to change.
        try:
            from motor.motor_asyncio import AsyncIOMotorGridFSBucket
            bucket = AsyncIOMotorGridFSBucket(self.db, bucket_name="report_bytes")
            await bucket.upload_from_stream_with_id(
                report_id, filename=f"{report_id}.bin",
                source=data, metadata={"mime": mime},
            )
            return f"gridfs://report_bytes/{report_id}"
        except Exception as exc:  # noqa: BLE001
            _log.warning("bytes_persist_failed", report_id=report_id, error=str(exc))
            return "inline://"

    async def _read_bytes(self, report_id: str) -> bytes:
        from motor.motor_asyncio import AsyncIOMotorGridFSBucket
        bucket = AsyncIOMotorGridFSBucket(self.db, bucket_name="report_bytes")
        buf = bytearray()
        stream = await bucket.open_download_stream(report_id)
        while True:
            chunk = await stream.readchunk()
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)
