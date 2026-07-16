"""Reusable MongoDB aggregation-pipeline builders.

Every analytics query in Module 10 flows through this service. Centralising
pipeline construction keeps them:

* index-aware (`user_id` first in `$match`),
* projection-tight (never emit sensitive fields),
* granularity-aware (share `$dateTrunc` semantics with `TimeFilterService`).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.logging import get_logger
from app.schemas.analytics_platform import Granularity, TimeRange

_log = get_logger(__name__)


class AggregationService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db

    # ---------------------------------------------------------- primitives
    @staticmethod
    def match_user(user_id: str, tr: TimeRange, *, field: str = "created_at") -> dict:
        return {"$match": {"user_id": user_id, field: {"$gte": tr.since, "$lte": tr.until}}}

    @staticmethod
    def group_by_time(
        granularity: Granularity, *, field: str = "created_at", extras: dict | None = None
    ) -> dict:
        _id: dict[str, Any] = {"bucket": {"$dateTrunc": {"date": f"${field}", "unit": granularity}}}
        if extras:
            _id.update(extras)
        return {"$group": {"_id": _id, "count": {"$sum": 1}}}

    @staticmethod
    def sort_by_time() -> dict:
        return {"$sort": {"_id.bucket": 1}}

    @staticmethod
    def facet(pipes: dict[str, list[dict]]) -> dict:
        return {"$facet": pipes}

    @staticmethod
    def bucket(field: str, boundaries: list[float], default: str = "other") -> dict:
        return {
            "$bucket": {
                "groupBy": f"${field}",
                "boundaries": boundaries,
                "default": default,
                "output": {"count": {"$sum": 1}},
            }
        }

    # ---------------------------------------------------------- runners
    async def run(self, collection: str, pipeline: list[dict]) -> list[dict]:
        try:
            cur = self.db[collection].aggregate(pipeline, allowDiskUse=True)
            return [d async for d in cur]
        except Exception as exc:  # noqa: BLE001
            _log.error("aggregation_failed", collection=collection, error=str(exc))
            return []

    async def count(self, collection: str, filter_: dict) -> int:
        try:
            return await self.db[collection].count_documents(filter_)
        except Exception as exc:  # noqa: BLE001
            _log.error("count_failed", collection=collection, error=str(exc))
            return 0

    # ---------------------------------------------------------- helpers
    @staticmethod
    def time_series(rows: Iterable[dict]) -> list[tuple[datetime, float]]:
        out: list[tuple[datetime, float]] = []
        for r in rows:
            b = r.get("_id", {}).get("bucket") if isinstance(r.get("_id"), dict) else r.get("_id")
            if isinstance(b, datetime):
                out.append((b, float(r.get("count", r.get("value", 0)))))
        return out

    @staticmethod
    def to_pie(rows: Iterable[dict], *, key: str = "_id", value: str = "count") -> list[dict]:
        return [{"label": str(r.get(key, "unknown")), "value": float(r.get(value, 0))} for r in rows]
