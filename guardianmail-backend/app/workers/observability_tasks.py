"""Phase 19 — observability Celery tasks."""
from __future__ import annotations

import asyncio

from celery import shared_task

from app.core.logging import get_logger

_log = get_logger(__name__)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(name="security.observability.probe_health")
def probe_health():
    from app.services.observability.health_service import ops_health_service
    try:
        return _run(ops_health_service.probe_all())
    except Exception as exc:  # pragma: no cover
        _log.warning("obs_probe_health_failed", err=str(exc))
        return {}


@shared_task(name="security.observability.snapshot_metrics")
def snapshot_metrics():
    """Persist a lightweight metric snapshot (dashboard fast-path)."""
    from app.database.mongodb import mongodb
    from app.models.observability import MetricSnapshot
    from app.repositories.observability import (
        MetricsSnapshotRepository,
        ObservabilityAlertRepository,
        OpsIncidentRepository,
    )

    async def _do():
        db = mongodb.db
        snap = MetricSnapshot(
            values={
                "active_alerts": len(
                    await ObservabilityAlertRepository(db).active(limit=500)
                ),
                "open_incidents": len(
                    await OpsIncidentRepository(db).open_incidents()
                ),
            }
        )
        await MetricsSnapshotRepository(db).insert(snap)
        return True

    try:
        return _run(_do())
    except Exception as exc:  # pragma: no cover
        _log.warning("obs_snapshot_failed", err=str(exc))
        return False
