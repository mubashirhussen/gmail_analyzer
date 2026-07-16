"""Operational health service — probes + Prometheus gauge updates.

Complements the SOC ``HealthMonitoringService`` (Module 18) by additionally
publishing ``guardian_component_up`` / ``guardian_component_latency_ms`` so
Prometheus/Grafana show the same status the SOC dashboard renders.
"""
from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.database.redis import redis_client
from app.services.observability.metrics_service import metrics_service

_log = get_logger(__name__)


class OpsHealthService:
    async def probe_all(self) -> dict[str, dict[str, Any]]:
        results = {
            "mongo": await self._probe(self._mongo, "mongo"),
            "redis": await self._probe(self._redis, "redis"),
            "api": {"status": "healthy", "latency_ms": 0.0},
        }
        metrics_service.set_component("api", healthy=True, latency_ms=0.0)
        return results

    async def _probe(self, fn, component: str) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            await fn()
            latency = round((time.perf_counter() - t) * 1000, 2)
            metrics_service.set_component(component, healthy=True, latency_ms=latency)
            return {"status": "healthy", "latency_ms": latency}
        except Exception as exc:
            latency = round((time.perf_counter() - t) * 1000, 2)
            metrics_service.set_component(component, healthy=False, latency_ms=latency)
            return {"status": "down", "latency_ms": latency,
                    "error": str(exc)[:200]}

    async def _mongo(self) -> None:
        await mongodb.db.command("ping")

    async def _redis(self) -> None:
        client = getattr(redis_client, "client", None) or getattr(
            redis_client, "_client", None
        )
        if client is None:
            raise RuntimeError("no_redis_client")
        await client.ping()


ops_health_service = OpsHealthService()
