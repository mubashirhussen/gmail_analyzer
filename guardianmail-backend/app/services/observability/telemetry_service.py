"""Telemetry service — persist spans to Mongo for the trace explorer.

Prometheus/OTel remain the source of truth for high-cardinality data.
This layer stores a bounded, downsampled subset accessible via the API
(``GET /api/v1/traces``) so analysts can search recent traces from the UI
without a Grafana/Tempo detour.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.observability import TelemetrySpan
from app.repositories.observability import TelemetryRepository

_log = get_logger(__name__)


class TelemetryService:
    async def record_span(
        self,
        *,
        trace_id: str,
        span_id: str,
        name: str,
        duration_ms: float,
        status: str = "ok",
        service: str = "guardianmail-api",
        parent_span_id: str | None = None,
        kind: str = "internal",
        attributes: dict[str, Any] | None = None,
    ) -> None:
        try:
            db = get_db()
            span = TelemetrySpan(
                trace_id=trace_id, span_id=span_id, name=name,
                duration_ms=float(duration_ms), status=status,
                service=service, parent_span_id=parent_span_id, kind=kind,
                attributes=attributes or {},
            )
            await TelemetryRepository(db).insert(span)
        except Exception as exc:  # pragma: no cover
            _log.debug("telemetry_persist_failed", err=str(exc))

    async def for_trace(self, trace_id: str) -> list[dict[str, Any]]:
        db = get_db()
        return await TelemetryRepository(db).for_trace(trace_id)

    async def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        db = get_db()
        return await TelemetryRepository(db).recent(limit=limit)


telemetry_service = TelemetryService()
