"""Aggregate health / readiness / liveness signals for Module 11.

Wraps the existing infra pings (Mongo, Redis, Celery, disk, memory) into
a single service consumed by `/api/v1/platform/health|ready|live|status`.
Never raises — always returns a structured payload so callers can render
degraded states without crashing.
"""
from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.core.config import settings
from app.database.mongodb import mongodb
from app.database.redis import redis_client

log = structlog.get_logger(__name__)

_STARTED_AT = time.time()


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    latency_ms: float
    detail: dict[str, Any] = field(default_factory=dict)


class HealthService:
    """Probe backend dependencies and produce a structured report."""

    def __init__(self) -> None:
        self._deep_cache: tuple[float, dict[str, Any]] | None = None
        self._deep_ttl = 5.0  # seconds

    async def liveness(self) -> dict[str, Any]:
        return {"status": "alive", "uptime_s": round(time.time() - _STARTED_AT, 3)}

    async def readiness(self) -> dict[str, Any]:
        mongo = await self._time(self._check_mongo)
        redis = await self._time(self._check_redis)
        checks = [mongo, redis]
        ready = all(c.ok for c in checks)
        return {
            "status": "ready" if ready else "degraded",
            "checks": [self._serialize(c) for c in checks],
        }

    async def deep_status(self) -> dict[str, Any]:
        now = time.time()
        if self._deep_cache and (now - self._deep_cache[0]) < self._deep_ttl:
            return self._deep_cache[1]
        checks = [
            await self._time(self._check_mongo),
            await self._time(self._check_redis),
            await self._time(self._check_celery),
            await self._time(self._check_disk),
            await self._time(self._check_memory),
        ]
        payload = {
            "status": "ok" if all(c.ok for c in checks) else "degraded",
            "env": settings.APP_ENV,
            "version": settings.APP_VERSION,
            "uptime_s": round(now - _STARTED_AT, 3),
            "checks": [self._serialize(c) for c in checks],
        }
        self._deep_cache = (now, payload)
        return payload

    # ---- individual probes ------------------------------------------------
    async def _check_mongo(self) -> Check:
        ok = False
        try:
            ok = await mongodb.ping()
        except Exception as exc:  # noqa: BLE001
            return Check("mongodb", False, 0.0, {"error": str(exc)[:200]})
        return Check("mongodb", ok, 0.0)

    async def _check_redis(self) -> Check:
        try:
            ok = await redis_client.ping()
        except Exception as exc:  # noqa: BLE001
            return Check("redis", False, 0.0, {"error": str(exc)[:200]})
        return Check("redis", ok, 0.0)

    async def _check_celery(self) -> Check:
        # Non-fatal: broker reachability implies workers can pick up jobs.
        try:
            ok = await redis_client.ping()
        except Exception as exc:  # noqa: BLE001
            return Check("celery_broker", False, 0.0, {"error": str(exc)[:200]})
        return Check("celery_broker", ok, 0.0)

    async def _check_disk(self) -> Check:
        try:
            usage = shutil.disk_usage("/")
            free_pct = usage.free / usage.total * 100
            return Check(
                "disk",
                free_pct > 5.0,
                0.0,
                {"free_pct": round(free_pct, 2), "total_gb": round(usage.total / 1e9, 2)},
            )
        except Exception as exc:  # noqa: BLE001
            return Check("disk", True, 0.0, {"error": str(exc)[:200]})

    async def _check_memory(self) -> Check:
        # /proc/meminfo when available; otherwise treat as OK.
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                data = {}
                for line in fh:
                    key, _, rest = line.partition(":")
                    parts = rest.strip().split()
                    if parts and parts[0].isdigit():
                        data[key] = int(parts[0])
            total = data.get("MemTotal", 0)
            avail = data.get("MemAvailable", 0)
            if not total:
                return Check("memory", True, 0.0, {})
            free_pct = avail / total * 100
            return Check(
                "memory",
                free_pct > 5.0,
                0.0,
                {"free_pct": round(free_pct, 2), "total_mb": round(total / 1024, 0)},
            )
        except FileNotFoundError:
            return Check("memory", True, 0.0, {"pid": os.getpid()})
        except Exception as exc:  # noqa: BLE001
            return Check("memory", True, 0.0, {"error": str(exc)[:200]})

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    async def _time(fn) -> Check:
        start = time.perf_counter()
        check = await fn()
        check.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return check

    @staticmethod
    def _serialize(c: Check) -> dict[str, Any]:
        return {
            "name": c.name,
            "ok": c.ok,
            "latency_ms": c.latency_ms,
            "detail": c.detail,
        }
