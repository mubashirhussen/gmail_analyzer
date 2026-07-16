"""Composed dashboard payloads with Redis-backed caching.

`DashboardService` is the single entry point the dashboard API talks to.
It orchestrates `AnalyticsService`, `SecurityScoreService`, `KPIService`,
and `TrendService`, then wraps the result in a per-user cache.

Cache invariants
----------------
* One Redis key per (user, scope, time_filter).
* Payload is JSON-encoded via Pydantic's `model_dump_json`.
* Cache miss => compute → store → tag in `dashboard_cache` collection.
* Cache hit  => increment hit counter (best-effort, never fatal).
"""
from __future__ import annotations

import json
import time

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.redis import redis_client
from app.models.dashboard_cache import DashboardCacheEntry
from app.repositories.dashboard_cache import DashboardCacheRepository
from app.schemas.analytics_platform import (
    DashboardOverview, KPICard, ScoreCard, TimeRange, TimelineEvent, TimelineGraph,
)
from app.services.analytics_platform.analytics_service import AnalyticsService
from app.services.analytics_platform.kpi_service import KPIService
from app.services.analytics_platform.redis_keys import (
    DASHBOARD_TTL_S, dashboard_key,
)
from app.services.analytics_platform.time_filters import TimeFilterService

_log = get_logger(__name__)


class DashboardService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.analytics = AnalyticsService(db)
        self.time = TimeFilterService()
        self.kpi = KPIService()
        self.cache_meta = DashboardCacheRepository(db)

    # -------------------------------------------------------------- OVERVIEW
    async def overview(
        self, user_id: str, tr: TimeRange, *, use_cache: bool = True,
    ) -> DashboardOverview:
        key = dashboard_key(user_id, "overview", tr.filter)
        if use_cache:
            cached = await self._get_cache(key)
            if cached:
                await self._record_hit(user_id, "overview", tr.filter)
                cached["from_cache"] = True
                return DashboardOverview.model_validate(cached)

        t0 = time.perf_counter()
        email = await self.analytics.email_analytics(user_id, tr)
        security = await self.analytics.security_analytics(user_id, tr)
        threats = await self.analytics.threat_analytics(user_id, tr)

        prev_tr = self.time.previous_period(tr)
        prev_email = await self.analytics.email_analytics(user_id, prev_tr)

        kpis: list[KPICard] = [
            self.kpi.card(key="emails_total", label="Total emails",
                          value=email.total, prev_value=prev_email.total),
            self.kpi.card(key="threats_total", label="Threats detected",
                          value=threats.total,
                          prev_value=(await self.analytics.threat_analytics(user_id, prev_tr)).total,
                          higher_is_better=False),
            self.kpi.card(key="protection_pct", label="Protection",
                          value=security.protection_pct, unit="%"),
            self.kpi.card(key="inbox_health", label="Inbox health",
                          value=email.inbox_health, unit="/100"),
            self.kpi.card(key="unread", label="Unread",
                          value=email.unread, higher_is_better=False),
        ]
        scores: list[ScoreCard] = [security.security_score, security.trust_score,
                                   security.threat_score]

        events = [TimelineEvent(at=e.at, label=e.label, severity=e.severity, ref=e.ref)
                  for e in threats.timeline.events[:20]]

        payload = DashboardOverview(
            time_range=tr, kpis=kpis, scores=scores, email=email,
            security=security,
            threats_summary={
                "total": threats.total, "dangerous_domains": threats.dangerous_domains[:5],
                "top_sender_risks": threats.top_sender_risks[:5],
                "attachment_threats": threats.attachment_threats,
            },
            recent_events=TimelineGraph(events=events),
            computed_at=now_utc(), from_cache=False,
        )
        compute_ms = int((time.perf_counter() - t0) * 1000)
        await self._store_cache(key, payload.model_dump(mode="json"), ttl=DASHBOARD_TTL_S)
        await self._store_meta(user_id, "overview", tr.filter, key, DASHBOARD_TTL_S, compute_ms)
        _log.info("dashboard_computed", user_id=user_id, scope="overview",
                  ms=compute_ms, filter=tr.filter)
        return payload

    # ---------------------------------------------------------- SCOPED READS
    async def scoped(self, user_id: str, scope: str, tr: TimeRange) -> dict:
        """Return the analytics payload for a single dashboard scope."""
        fn = {
            "security": self.analytics.security_analytics,
            "threats": self.analytics.threat_analytics,
            "emails": self.analytics.email_analytics,
            "domains": self.analytics.domain_analytics,
            "users": self.analytics.user_analytics,
            "ai": self.analytics.ai_analytics,
            "ocr": self.analytics.ocr_analytics,
            "complaints": self.analytics.complaint_analytics,
        }.get(scope)
        if not fn:
            raise ValueError(f"unknown scope: {scope}")
        data = await fn(user_id, tr)
        return data.model_dump(mode="json") if hasattr(data, "model_dump") else data

    # ------------------------------------------------------- invalidate hooks
    async def invalidate_user(self, user_id: str) -> int:
        deleted = 0
        try:
            pattern = f"am:dash:{user_id}:*"
            async for k in redis_client.client.scan_iter(match=pattern, count=200):
                await redis_client.client.delete(k); deleted += 1
        except Exception as exc:  # noqa: BLE001
            _log.warning("cache_invalidate_failed", user_id=user_id, error=str(exc))
        return deleted

    # ---------------------------------------------------------------- redis
    async def _get_cache(self, key: str) -> dict | None:
        try:
            raw = await redis_client.client.get(key)
            return json.loads(raw) if raw else None
        except Exception as exc:  # noqa: BLE001
            _log.warning("cache_read_failed", key=key, error=str(exc))
            return None

    async def _store_cache(self, key: str, payload: dict, *, ttl: int) -> None:
        try:
            await redis_client.client.set(key, json.dumps(payload, default=str), ex=ttl)
        except Exception as exc:  # noqa: BLE001
            _log.warning("cache_write_failed", key=key, error=str(exc))

    async def _store_meta(
        self, user_id: str, scope: str, tf: str, key: str, ttl: int, compute_ms: int
    ) -> None:
        try:
            await self.cache_meta.upsert(DashboardCacheEntry(
                user_id=user_id, scope=scope, time_filter=tf, key=key,
                ttl_s=ttl, computed_at=now_utc(), compute_ms=compute_ms,
            ))
        except Exception as exc:  # noqa: BLE001
            _log.warning("cache_meta_upsert_failed", error=str(exc))

    async def _record_hit(self, user_id: str, scope: str, tf: str) -> None:
        try:
            await self.cache_meta.record_hit(user_id, scope, tf)
        except Exception:  # noqa: BLE001
            pass
