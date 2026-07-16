"""Canonical resolution of user-facing time filters into UTC ranges.

Frontend passes short filter names (`last_7_days`, `this_month`, ...) or a
custom range. Every service in the platform uses this resolver so the
dashboard, KPI, trend, and report layers agree on window boundaries.
"""
from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
from typing import Literal

from app.schemas.analytics_platform import Granularity, TimeFilter, TimeRange

_UTC = timezone.utc


def _start_of_day(dt: datetime) -> datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _end_of_day(dt: datetime) -> datetime:
    return dt.replace(hour=23, minute=59, second=59, microsecond=999_000)


class TimeFilterService:
    """Pure resolver — no I/O, safe to call at request time."""

    def resolve(
        self,
        f: TimeFilter,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        granularity: Granularity | None = None,
    ) -> TimeRange:
        now = datetime.now(_UTC)
        today = _start_of_day(now)

        if f == "today":
            s, u = today, _end_of_day(now)
            g: Granularity = "hour"
        elif f == "yesterday":
            s = today - timedelta(days=1)
            u = _end_of_day(s)
            g = "hour"
        elif f == "last_7_days":
            s = today - timedelta(days=6)
            u = _end_of_day(now)
            g = "day"
        elif f == "last_30_days":
            s = today - timedelta(days=29)
            u = _end_of_day(now)
            g = "day"
        elif f == "last_90_days":
            s = today - timedelta(days=89)
            u = _end_of_day(now)
            g = "week"
        elif f == "this_month":
            s = today.replace(day=1)
            u = _end_of_day(now)
            g = "day"
        elif f == "last_month":
            first_this = today.replace(day=1)
            last_prev = first_this - timedelta(days=1)
            s = last_prev.replace(day=1)
            u = _end_of_day(last_prev.replace(day=monthrange(last_prev.year, last_prev.month)[1]))
            g = "day"
        elif f == "custom":
            if since is None or until is None:
                raise ValueError("custom time filter requires since and until")
            s, u = since.astimezone(_UTC), until.astimezone(_UTC)
            g = granularity or self._auto_granularity(s, u)
        else:
            raise ValueError(f"unknown time filter: {f}")

        return TimeRange(filter=f, since=s, until=u, granularity=granularity or g)

    def previous_period(self, tr: TimeRange) -> TimeRange:
        """Same-length window immediately before `tr` — used for delta_pct."""
        span = tr.until - tr.since
        prev_until = tr.since - timedelta(microseconds=1)
        prev_since = prev_until - span
        return TimeRange(
            filter="custom",
            since=prev_since,
            until=prev_until,
            granularity=tr.granularity,
        )

    def _auto_granularity(self, since: datetime, until: datetime) -> Granularity:
        span_days = (until - since).days
        if span_days <= 2:
            return "hour"
        if span_days <= 45:
            return "day"
        if span_days <= 180:
            return "week"
        return "month"

    def mongo_date_trunc(self, granularity: Granularity) -> dict:
        """Emit a $dateTrunc spec compatible with MongoDB aggregation."""
        return {"unit": granularity}
