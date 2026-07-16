"""Phase 18 — SOC Celery tasks.

Periodic aggregations, health snapshots, and report generation. All tasks
are additive and idempotent — safe to schedule alongside existing workers.
"""
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


@shared_task(name="security.soc.snapshot_dashboard")
def snapshot_dashboard():
    from app.services.soc.dashboard_service import dashboard_service
    try:
        _run(dashboard_service.build(use_cache=False))
        return {"ok": True}
    except Exception as exc:  # pragma: no cover
        _log.warning("soc_dashboard_snapshot_failed", err=str(exc))
        return {"ok": False, "error": str(exc)}


@shared_task(name="security.soc.snapshot_health")
def snapshot_health():
    from app.services.soc.health_service import health_service
    try:
        _run(health_service.snapshot_all())
        return {"ok": True}
    except Exception as exc:  # pragma: no cover
        _log.warning("soc_health_snapshot_failed", err=str(exc))
        return {"ok": False, "error": str(exc)}


@shared_task(name="security.soc.generate_report")
def generate_report(kind: str = "daily"):
    from app.services.soc.report_service import report_service
    try:
        return _run(report_service.generate(kind=kind))
    except Exception as exc:  # pragma: no cover
        _log.warning("soc_report_failed", err=str(exc))
        return {"ok": False, "error": str(exc)}


@shared_task(name="security.soc.ingest_detection")
def ingest_detection(detection: dict):
    from app.services.soc.soc_service import soc_service
    try:
        return _run(soc_service.ingest_detection(detection))
    except Exception as exc:  # pragma: no cover
        _log.warning("soc_ingest_task_failed", err=str(exc))
        return None
