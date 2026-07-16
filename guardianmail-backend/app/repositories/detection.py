"""Detection repositories — detection results, behaviour profiles, fraud indicators."""
from __future__ import annotations

from typing import Any

from pymongo import ASCENDING, DESCENDING

from app.core.clock import now_utc
from app.models.detection import (
    DetectionResult,
    FraudIndicator,
    SenderBehaviorProfile,
)
from app.repositories.base import BaseRepository


class DetectionRepository(BaseRepository[DetectionResult]):
    collection_name = "detections"
    model = DetectionResult
    soft_delete = True

    async def latest_for_email(self, email_id: str) -> dict | None:
        return await self.find_one(
            {"email_id": email_id}, sort=[("created_at", DESCENDING)]
        )

    async def list_for_user(
        self, user_id: str, *, page: int = 1, page_size: int = 25,
        min_score: float | None = None,
    ):
        f: dict[str, Any] = {"user_id": user_id}
        if min_score is not None:
            f["risk_score"] = {"$gte": min_score}
        return await self.paginate(
            f, page=page, page_size=page_size,
            sort=[("created_at", DESCENDING)],
        )


class BehaviorRepository(BaseRepository[SenderBehaviorProfile]):
    collection_name = "sender_behavior"
    model = SenderBehaviorProfile
    soft_delete = False

    async def get(self, user_id: str, sender: str) -> dict | None:
        return await self.find_one(
            {"user_id": user_id, "sender": (sender or "").lower()}
        )

    async def observe(
        self, *, user_id: str, sender: str, domain: str | None,
        subject_len: int, verdict: str | None, flagged: bool,
    ) -> dict:
        key = {"user_id": user_id, "sender": (sender or "").lower()}
        now = now_utc()
        existing = await self.find_one(key)
        if not existing:
            profile = SenderBehaviorProfile(
                user_id=user_id, sender=key["sender"],
                first_seen=now, last_seen=now, total_messages=1,
                domains=[domain] if domain else [],
                avg_subject_len=float(subject_len or 0),
                flagged_messages=1 if flagged else 0,
                last_verdict=verdict,
            )
            await self.insert_one(profile.to_mongo())
            return profile.model_dump(by_alias=True)

        total = int(existing.get("total_messages", 0)) + 1
        prev_avg = float(existing.get("avg_subject_len", 0.0))
        new_avg = ((prev_avg * (total - 1)) + float(subject_len or 0)) / total
        update: dict[str, Any] = {
            "$set": {
                "last_seen": now,
                "avg_subject_len": new_avg,
                "last_verdict": verdict,
                "updated_at": now,
            },
            "$inc": {"total_messages": 1, "flagged_messages": 1 if flagged else 0},
        }
        if domain and domain not in (existing.get("domains") or []):
            update["$addToSet"] = {"domains": domain}
        await self.collection.update_one(key, update)
        return await self.find_one(key) or {}


class FraudIndicatorRepository(BaseRepository[FraudIndicator]):
    collection_name = "fraud_indicators"
    model = FraudIndicator
    soft_delete = False

    async def list_for_user(self, user_id: str, *, page: int = 1, page_size: int = 25):
        return await self.paginate(
            {"user_id": user_id}, page=page, page_size=page_size,
            sort=[("created_at", DESCENDING)],
        )

    async def list_for_detection(self, detection_id: str) -> list[dict]:
        cur = self.collection.find({"detection_id": detection_id}).sort("created_at", ASCENDING)
        return await cur.to_list(length=200)
