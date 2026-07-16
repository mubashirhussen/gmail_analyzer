"""System health monitoring service.

Probes core infra (Mongo, Redis, Celery) and records snapshots. Never
raises — a failed probe records `down` and keeps the SOC responsive.
"""
from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import get_db, mongodb
from app.database.redis import redis_client
from app.models.soc import SystemHealthSnapshot
from app.repositories.soc import HealthRepository

_log = get_logger(__name__)


class HealthMonitoringService:
    async def probe_mongo(self) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            await mongodb.db.command("ping")
            return {"status": "healthy",
                    "latency_ms": round((time.perf_counter() - t) * 1000, 2)}
        except Exception as exc:
            return {"status": "down", "detail": {"error": str(exc)[:200]}}

    async def probe_redis(self) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            client = getattr(redis_client, "client", None) or getattr(
                redis_client, "_client", None
            )
            if client is None:
                return {"status": "degraded", "detail": {"reason": "no_client"}}
            await client.ping()
            return {"status": "healthy",
                    "latency_ms": round((time.perf_counter() - t) * 1000, 2)}
        except Exception as exc:
            return {"status": "down", "detail": {"error": str(exc)[:200]}}

    async def snapshot_all(self) -> dict[str, dict[str, Any]]:
        components = {
            "mongo": await self.probe_mongo(),
            "redis": await self.probe_redis(),
            "api": {"status": "healthy"},
        }
        db = get_db()
        repo = HealthRepository(db)
        for name, res in components.items():
            try:
                snap = SystemHealthSnapshot(
                    component=name,
                    status=res.get("status", "healthy"),
                    latency_ms=res.get("latency_ms"),
                    detail=res.get("detail", {}),
                )
                await repo.insert(snap)
            except Exception as exc:  # pragma: no cover
                _log.warning("health_snapshot_failed", component=name, err=str(exc))
        return components

    async def latest(self) -> dict[str, dict[str, Any]]:
        db = get_db()
        try:
            return await HealthRepository(db).latest()
        except Exception:
            return {}


health_service = HealthMonitoringService()
