"""Links device fingerprints to suspicious artifacts + signals detected.

Every analyzed artifact from a device is logged so we can answer:
  "Which devices have interacted with phishing content?"
  "Which suspicious signals were detected on that device?"
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.database.mongodb import get_db


async def link_artifact(*, user_id: str, device_fingerprint: str | None,
                        artifact_hash: str, artifact_kind: str,
                        verdict: str, risk_score: int, signals: list[dict]) -> None:
    if not device_fingerprint:
        return
    now = datetime.now(timezone.utc)
    db = get_db()
    await db.device_artifacts.insert_one({
        "user_id": user_id,
        "device_fingerprint": device_fingerprint,
        "artifact_hash": artifact_hash,
        "artifact_kind": artifact_kind,
        "verdict": verdict,
        "risk_score": risk_score,
        "signal_categories": sorted({s.get("category") for s in signals if s.get("category")}),
        "at": now,
    })
    if verdict in ("phishing", "fraud", "suspicious"):
        await db.security_events.insert_one({
            "user_id": user_id,
            "device_fingerprint": device_fingerprint,
            "kind": "suspicious_artifact",
            "severity": "high" if verdict == "phishing" else "medium",
            "summary": f"Device processed {verdict} {artifact_kind} (score {risk_score})",
            "meta": {"artifact_hash": artifact_hash, "signals": [s.get("category") for s in signals]},
            "created_at": now,
        })


async def device_risk_summary(user_id: str, device_fingerprint: str) -> dict:
    db = get_db()
    pipeline = [
        {"$match": {"user_id": user_id, "device_fingerprint": device_fingerprint}},
        {"$group": {
            "_id": "$verdict",
            "count": {"$sum": 1},
            "avg_risk": {"$avg": "$risk_score"},
            "categories": {"$addToSet": "$signal_categories"},
        }},
    ]
    rows = [r async for r in db.device_artifacts.aggregate(pipeline)]
    return {"device_fingerprint": device_fingerprint, "breakdown": rows}
