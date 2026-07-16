"""BehaviorAnalysisService — sender history, first-contact, anomalies."""
from __future__ import annotations

import re
from typing import Any

from app.database.mongodb import get_db
from app.repositories.detection import BehaviorRepository


def _domain(addr: str | None) -> str:
    if not addr:
        return ""
    m = re.search(r"@([\w\.-]+)", addr)
    return m.group(1).lower() if m else ""


class BehaviorAnalysisService:
    async def evaluate(
        self, *, user_id: str, sender: str | None,
        subject: str | None, verdict: str | None, flagged: bool,
    ) -> dict[str, Any]:
        db = get_db()
        repo = BehaviorRepository(db)
        sender_norm = (sender or "").lower()
        profile = await repo.get(user_id, sender_norm) if sender_norm else None
        first_contact = profile is None

        signals: list[str] = []
        score = 0.0
        if first_contact and sender_norm:
            signals.append("first_contact")
            score += 10

        if profile:
            total = int(profile.get("total_messages") or 0)
            flagged_before = int(profile.get("flagged_messages") or 0)
            avg_len = float(profile.get("avg_subject_len") or 0)
            cur_len = len(subject or "")
            if flagged_before and total and (flagged_before / total) > 0.3:
                signals.append("historical_flagged_sender")
                score += 25
            if avg_len and cur_len and abs(cur_len - avg_len) > max(30, avg_len):
                signals.append("subject_length_anomaly")
                score += 5
            if profile.get("trusted"):
                score -= 15
                signals.append("trusted_sender")

        # Observe (learn for next time). Persistence failures must never
        # break detection.
        try:
            profile_after = await repo.observe(
                user_id=user_id, sender=sender_norm,
                domain=_domain(sender_norm), subject_len=len(subject or ""),
                verdict=verdict, flagged=flagged,
            )
        except Exception:
            profile_after = profile or {}

        return {
            "first_contact": first_contact,
            "sender_history_count": int((profile or {}).get("total_messages") or 0),
            "flagged_history_count": int((profile or {}).get("flagged_messages") or 0),
            "signals": signals,
            "score": max(-15.0, min(40.0, score)),
            "trusted": bool((profile or {}).get("trusted")),
            "profile_id": profile_after.get("_id") if profile_after else None,
        }


behavior_analysis_service = BehaviorAnalysisService()
