"""Trend series builder + reader.

Two responsibilities:

1. **Build** — background workers call `build_metric` to compute a metric
   time series and persist per-bucket values in `trend_series`. This is
   how we get O(1) reads for dashboard trend widgets over long windows.
2. **Read** — the dashboard API calls `read` for a metric+range and gets
   an ordered `LineChart`-ready payload.

Metrics understood out-of-the-box:

* `emails_total`, `emails_spam`, `emails_flagged`     (from `emails`)
* `threats_total`, `threats_critical`                 (from `threats`)
* `security_score`                                    (from `analytics`)
* `ai_verdicts_phishing`                              (from `ai_reports`)
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.models.trend_series import TrendSeries
from app.repositories.trend_series import TrendSeriesRepository
from app.schemas.analytics_platform import (
    ChartSeries, Granularity, LineChart, SeriesPoint, TimeRange,
)

_log = get_logger(__name__)


def _match(user_id: str, tr: TimeRange, extra: dict | None = None) -> dict:
    q: dict = {"user_id": user_id, "created_at": {"$gte": tr.since, "$lte": tr.until}}
    if extra:
        q.update(extra)
    return q


_METRIC_SPECS: dict[str, dict] = {
    "emails_total":       {"col": "emails",      "extra": {}},
    "emails_spam":        {"col": "emails",      "extra": {"labels": "SPAM"}},
    "emails_flagged":     {"col": "emails",      "extra": {"is_starred": True}},
    "threats_total":      {"col": "threats",     "extra": {}},
    "threats_critical":   {"col": "threats",     "extra": {"severity": "critical"}},
    "ai_verdicts_phishing": {"col": "ai_reports", "extra": {"verdict": "phishing"}},
}


class TrendService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.repo = TrendSeriesRepository(db)

    # ---------------------------------------------------------------- build
    async def build_metric(
        self, user_id: str, metric: str, tr: TimeRange
    ) -> int:
        spec = _METRIC_SPECS.get(metric)
        if not spec:
            _log.warning("unknown_metric", metric=metric)
            return 0
        pipeline = [
            {"$match": _match(user_id, tr, spec["extra"])},
            {"$group": {"_id": {"$dateTrunc":
                {"date": "$created_at", "unit": tr.granularity}}, "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
        n = 0
        async for row in self.db[spec["col"]].aggregate(pipeline):
            bucket = row["_id"]
            if not isinstance(bucket, datetime):
                continue
            await self.repo.upsert(TrendSeries(
                user_id=user_id, metric=metric, granularity=tr.granularity,
                bucket_start=bucket, value=float(row["count"]),
                computed_at=now_utc(),
            ))
            n += 1
        return n

    async def build_security_score_series(self, user_id: str, tr: TimeRange) -> int:
        n = 0
        async for r in self.db.analytics.find(
            {"user_id": user_id, "at": {"$gte": tr.since, "$lte": tr.until}},
            sort=[("at", 1)],
        ):
            await self.repo.upsert(TrendSeries(
                user_id=user_id, metric="security_score",
                granularity=tr.granularity, bucket_start=r["at"],
                value=float(r.get("security_score", 0)), computed_at=now_utc(),
            ))
            n += 1
        return n

    # ----------------------------------------------------------------- read
    async def read(self, user_id: str, metric: str, tr: TimeRange) -> LineChart:
        rows = await self.repo.range(
            user_id, metric,
            granularity=tr.granularity, since=tr.since, until=tr.until,
        )
        return LineChart(
            x_label="time", y_label=metric,
            series=[ChartSeries(name=metric,
                    points=[SeriesPoint(x=r.bucket_start, y=r.value) for r in rows])],
        )
