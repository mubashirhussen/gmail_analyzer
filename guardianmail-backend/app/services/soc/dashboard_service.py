"""SOC dashboard aggregation service."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.core.clock import now_utc
from app.database.mongodb import get_db
from app.database.redis import redis_client
from app.repositories.soc import (
    AlertRepository,
    IncidentRepository,
    since_hours,
)
from app.services.soc.health_service import health_service


CACHE_KEY = "soc:dashboard:v1"
CACHE_TTL = 20  # seconds


class DashboardService:
    async def build(self, *, use_cache: bool = True) -> dict[str, Any]:
        if use_cache:
            cached = await self._cache_get()
            if cached is not None:
                return cached
        db = get_db()
        inc = IncidentRepository(db)
        alerts = AlertRepository(db)
        since_24 = since_hours(24)

        sev_24 = await inc.counts_by("severity", since=since_24)
        status_all = await inc.counts_by("status")
        type_24 = await inc.counts_by("incident_type", since=since_24)
        top_domains = await inc.top_domains(since=since_24, limit=10)
        recent_cur = inc.col.find(
            {"deleted_at": None}, projection=None,
        ).sort("created_at", -1).limit(10)
        recent = [d async for d in recent_cur]
        active_alerts = await alerts.active(limit=25)
        health = await health_service.latest()
        if not health:
            health = await health_service.snapshot_all()

        widgets = {
            "emails_scanned_today": await self._safe_count(db, "emails", since_24),
            "threats_detected_today": await self._safe_count(db, "threats", since_24),
            "critical_threats_today": sev_24.get("critical", 0),
            "high_risk_today": sev_24.get("high", 0),
            "safe_emails_today": max(
                0,
                (await self._safe_count(db, "emails", since_24))
                - sum(sev_24.values()),
            ),
            "pending_investigations": status_all.get("investigating", 0)
            + status_all.get("awaiting_review", 0),
            "open_complaints": await self._safe_count(db, "complaints", None,
                                                     extra={"status": {"$ne": "resolved"}}),
            "resolved_incidents": status_all.get("resolved", 0)
            + status_all.get("closed", 0),
            "active_alerts": len(active_alerts),
            "severity_breakdown_24h": sev_24,
            "type_breakdown_24h": type_24,
            "status_breakdown": status_all,
            "active_sessions": await self._safe_count(db, "sessions", None,
                                                     extra={"revoked_at": None}),
        }

        dashboard = {
            "generated_at": now_utc(),
            "widgets": widgets,
            "health": health,
            "top_domains": top_domains,
            "recent_incidents": recent,
            "active_alerts": active_alerts,
        }
        await self._cache_set(dashboard)
        return dashboard

    async def _safe_count(
        self,
        db,
        collection: str,
        since,
        *,
        extra: dict | None = None,
    ) -> int:
        try:
            f: dict[str, Any] = {"deleted_at": None} if "deleted_at" not in (extra or {}) else {}
            if extra:
                f.update(extra)
            if since is not None:
                f["created_at"] = {"$gte": since}
            return await db[collection].count_documents(f)
        except Exception:
            return 0

    async def _cache_get(self) -> dict[str, Any] | None:
        try:
            import json
            client = getattr(redis_client, "client", None) or getattr(
                redis_client, "_client", None
            )
            if not client:
                return None
            raw = await client.get(CACHE_KEY)
            if not raw:
                return None
            return json.loads(raw)
        except Exception:
            return None

    async def _cache_set(self, data: dict[str, Any]) -> None:
        try:
            import json
            client = getattr(redis_client, "client", None) or getattr(
                redis_client, "_client", None
            )
            if not client:
                return
            payload = json.dumps(data, default=str)
            await client.set(CACHE_KEY, payload, ex=CACHE_TTL)
        except Exception:
            return


dashboard_service = DashboardService()
