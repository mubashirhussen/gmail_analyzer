"""Trend-series repository — append and range-scan metric buckets."""
from __future__ import annotations

from datetime import datetime

from pymongo import ASCENDING

from app.models.trend_series import TrendSeries
from app.repositories.base import BaseRepository


class TrendSeriesRepository(BaseRepository[TrendSeries]):
    collection_name = "trend_series"
    model = TrendSeries
    soft_delete = False

    async def upsert(self, doc: TrendSeries) -> None:
        payload = doc.model_dump(by_alias=True)
        await self.col.update_one(
            {
                "user_id": doc.user_id,
                "metric": doc.metric,
                "granularity": doc.granularity,
                "bucket_start": doc.bucket_start,
                "dims": doc.dims,
            },
            {"$set": payload},
            upsert=True,
        )

    async def range(
        self,
        user_id: str,
        metric: str,
        *,
        granularity: str,
        since: datetime,
        until: datetime,
        dims: dict | None = None,
    ) -> list[TrendSeries]:
        q: dict = {
            "user_id": user_id,
            "metric": metric,
            "granularity": granularity,
            "bucket_start": {"$gte": since, "$lte": until},
        }
        if dims:
            q["dims"] = dims
        return await self.find_many(q, sort=[("bucket_start", ASCENDING)], limit=5000)
