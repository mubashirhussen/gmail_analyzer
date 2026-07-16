"""Celery tasks for the analytics platform (Module 10).

Tasks
-----
* `analytics_platform.daily_rollup`     — nightly per-user snapshot rebuild.
* `analytics_platform.weekly_rollup`    — weekly aggregate.
* `analytics_platform.monthly_rollup`   — monthly aggregate.
* `analytics_platform.warm_dashboard`   — pre-computes overview cache.
* `analytics_platform.build_trends`     — refresh persisted trend series.
* `analytics_platform.generate_report`  — async report generation.
* `analytics_platform.cleanup_cache`    — evict stale cache metadata rows.

Every task is idempotent and safe to retry. The Beat schedule wires the
periodic ones in `app.workers.scheduler`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import mongodb
from app.repositories.dashboard_cache import DashboardCacheRepository
from app.schemas.analytics_platform import TimeRange
from app.services.analytics_platform.analytics_service import AnalyticsService
from app.services.analytics_platform.dashboard_service import DashboardService
from app.services.analytics_platform.reporting_service import ReportingService
from app.services.analytics_platform.time_filters import TimeFilterService
from app.services.analytics_platform.trend_service import TrendService
from app.workers.celery_app import celery

_log = get_logger(__name__)
_UTC = timezone.utc


async def _boot():
    if mongodb.db is None:
        await mongodb.connect()


async def _iter_active_user_ids(limit: int = 5000) -> list[str]:
    await _boot()
    ids: list[str] = []
    async for u in mongodb.db.users.find(
        {"status": "active"}, {"_id": 1}
    ).limit(limit):
        ids.append(str(u["_id"]))
    return ids


def _tr(days: int) -> TimeRange:
    tf = TimeFilterService()
    if days == 1:
        return tf.resolve("today")
    if days == 7:
        return tf.resolve("last_7_days")
    if days == 30:
        return tf.resolve("last_30_days")
    if days == 90:
        return tf.resolve("last_90_days")
    now = datetime.now(_UTC)
    return tf.resolve("custom", since=now - timedelta(days=days),
                      until=now, granularity="day")


# ============================================================ ROLLUPS

@celery.task(name="analytics_platform.daily_rollup", bind=True, max_retries=3,
             default_retry_delay=60)
def daily_rollup(self) -> dict:
    async def run() -> dict:
        await _boot()
        analytics = AnalyticsService(mongodb.db)
        scores = analytics.scores
        tr = _tr(1)
        n = 0
        for uid in await _iter_active_user_ids():
            try:
                em = await analytics.email_analytics(uid, tr)
                thr = await analytics.threat_analytics(uid, tr)
                sec = await analytics.security_analytics(uid, tr)
                snap = {
                    "user_id": uid, "period": "day", "at": now_utc(),
                    "threat_score": sec.threat_score.score,
                    "security_score": sec.security_score.score,
                    "trust_score": sec.trust_score.score,
                    "privacy_score": 90,
                    "emails_total": em.total, "emails_scanned": em.total,
                    "threats_detected": thr.total,
                    "counts": {
                        "safe": max(0, em.total - thr.total),
                        "suspicious": max(0, thr.total - sec.blocked_count),
                        "phishing": sum(1 for s in thr.by_category.slices if s.label == "phishing"),
                        "fraud": sum(1 for s in thr.by_category.slices if s.label == "fraud"),
                    },
                    "top_categories": [s.model_dump() for s in thr.by_category.slices[:5]],
                    "top_sender_domains": thr.top_sources[:5],
                }
                await mongodb.db.analytics.insert_one(snap); n += 1
            except Exception as exc:  # noqa: BLE001
                _log.error("daily_rollup_user_failed", user_id=uid, error=str(exc))
        return {"snapshots": n}
    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)


@celery.task(name="analytics_platform.weekly_rollup")
def weekly_rollup() -> dict:
    return _period_rollup("week", days=7)


@celery.task(name="analytics_platform.monthly_rollup")
def monthly_rollup() -> dict:
    return _period_rollup("month", days=30)


def _period_rollup(period: str, *, days: int) -> dict:
    async def run() -> dict:
        await _boot()
        analytics = AnalyticsService(mongodb.db)
        tr = _tr(days)
        n = 0
        for uid in await _iter_active_user_ids():
            try:
                em = await analytics.email_analytics(uid, tr)
                thr = await analytics.threat_analytics(uid, tr)
                sec = await analytics.security_analytics(uid, tr)
                await mongodb.db.analytics.insert_one({
                    "user_id": uid, "period": period, "at": now_utc(),
                    "security_score": sec.security_score.score,
                    "trust_score": sec.trust_score.score,
                    "threat_score": sec.threat_score.score,
                    "emails_total": em.total, "threats_detected": thr.total,
                    "counts": {}, "top_categories": [], "top_sender_domains": [],
                })
                n += 1
            except Exception as exc:  # noqa: BLE001
                _log.error("period_rollup_failed", period=period,
                           user_id=uid, error=str(exc))
        return {"period": period, "snapshots": n}
    return asyncio.run(run())


# ============================================================ CACHE WARMING

@celery.task(name="analytics_platform.warm_dashboard")
def warm_dashboard(user_id: str | None = None, time_filter: str = "last_30_days") -> dict:
    async def run() -> dict:
        await _boot()
        service = DashboardService(mongodb.db)
        tf = TimeFilterService()
        tr = tf.resolve(time_filter)  # type: ignore[arg-type]
        uids = [user_id] if user_id else await _iter_active_user_ids(500)
        n = 0
        for uid in uids:
            try:
                await service.overview(uid, tr, use_cache=False)
                n += 1
            except Exception as exc:  # noqa: BLE001
                _log.error("warm_dashboard_failed", user_id=uid, error=str(exc))
        return {"warmed": n, "time_filter": time_filter}
    return asyncio.run(run())


# ============================================================ TRENDS

@celery.task(name="analytics_platform.build_trends")
def build_trends(user_id: str, time_filter: str = "last_30_days") -> dict:
    async def run() -> dict:
        await _boot()
        service = TrendService(mongodb.db)
        tf = TimeFilterService()
        tr = tf.resolve(time_filter)  # type: ignore[arg-type]
        metrics = ["emails_total", "emails_spam", "emails_flagged",
                   "threats_total", "threats_critical", "ai_verdicts_phishing"]
        results: dict[str, int] = {}
        for m in metrics:
            try:
                results[m] = await service.build_metric(user_id, m, tr)
            except Exception as exc:  # noqa: BLE001
                _log.error("build_trend_failed", user_id=user_id,
                           metric=m, error=str(exc))
                results[m] = -1
        results["security_score"] = await service.build_security_score_series(user_id, tr)
        return {"user_id": user_id, "buckets": results}
    return asyncio.run(run())


# ============================================================ REPORTS

@celery.task(name="analytics_platform.generate_report", bind=True,
             max_retries=3, default_retry_delay=60)
def generate_report(self, report_id: str) -> dict:
    async def run() -> dict:
        await _boot()
        service = ReportingService(mongodb.db)
        rec = await service.generate_now(report_id)
        return {"report_id": rec.id, "status": rec.status,
                "size": rec.size_bytes, "fmt": rec.fmt}
    try:
        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc)


# ============================================================ CACHE CLEANUP

@celery.task(name="analytics_platform.cleanup_cache")
def cleanup_cache() -> dict:
    async def run() -> dict:
        await _boot()
        repo = DashboardCacheRepository(mongodb.db)
        cutoff = now_utc() - timedelta(hours=24)
        res = await repo.col.delete_many({"computed_at": {"$lt": cutoff}})
        return {"deleted": int(res.deleted_count or 0)}
    return asyncio.run(run())
