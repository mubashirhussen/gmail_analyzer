"""SOC report generation service."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.core.clock import now_utc
from app.database.mongodb import get_db
from app.models.soc import SOCReport
from app.repositories.soc import IncidentRepository, ReportRepository


class ReportService:
    async def generate(
        self,
        *,
        kind: str,
        period_hours: int | None = None,
        generated_by: str = "system",
    ) -> dict[str, Any]:
        hours = period_hours or {"daily": 24, "weekly": 24 * 7,
                                 "monthly": 24 * 30}.get(kind, 24)
        end = now_utc()
        start = end - timedelta(hours=hours)
        db = get_db()
        inc = IncidentRepository(db)

        sev = await inc.counts_by("severity", since=start)
        types = await inc.counts_by("incident_type", since=start)
        status = await inc.counts_by("status", since=start)
        top_domains = await inc.top_domains(since=start, limit=10)
        total = sum(sev.values())

        report = SOCReport(
            kind=kind, period_start=start, period_end=end,
            generated_by=generated_by,
            summary={
                "total_incidents": total,
                "severity_breakdown": sev,
                "type_breakdown": types,
                "status_breakdown": status,
            },
            sections=[
                {"title": "Top Domains", "data": top_domains},
                {"title": "Severity", "data": sev},
                {"title": "Attack Types", "data": types},
            ],
        )
        inserted = await ReportRepository(db).insert(report)
        doc = await ReportRepository(db).find_by_id(str(inserted))
        return doc.model_dump(by_alias=True) if doc else {"_id": str(inserted)}

    async def list_reports(self, *, page: int = 1, page_size: int = 25):
        db = get_db()
        return await ReportRepository(db).paginate(
            {}, page=page, page_size=page_size,
        )


report_service = ReportService()
