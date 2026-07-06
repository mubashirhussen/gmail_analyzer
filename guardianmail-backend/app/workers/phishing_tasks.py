"""Celery tasks that run the full phishing pipeline."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.database.mongodb import mongodb
from app.services.phishing.pipeline import analyze_message
from app.services.notifications.sender import notify_threat
from app.services.automation.rules import apply_rules
from app.workers.celery_app import celery


async def _bootstrap_db():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="threat.analyze_email")
def analyze_email(user_id: str, payload: dict) -> dict:
    async def run():
        await _bootstrap_db()
        ai = await analyze_message(user_id, payload)
        threat = await mongodb.db.threats.find_one(
            {"user_id": user_id}, sort=[("created_at", -1)]
        )
        if threat:
            await apply_rules(user_id, threat)
            await notify_threat(user_id, ai.get("verdict", "safe"),
                                int(ai.get("risk_score", 0)),
                                payload.get("subject", ""))
        return ai
    return asyncio.run(run())


@celery.task(name="threat.analyze_gmail_message")
def analyze_gmail_message(user_id: str, gmail_id: str) -> dict:
    async def run():
        await _bootstrap_db()
        db = mongodb.db
        assert db is not None
        email = await db.emails.find_one({"gmail_id": gmail_id, "user_id": user_id})
        if not email:
            return {"skipped": True}
        await db.emails.update_one({"_id": email["_id"]},
                                   {"$set": {"analysis_status": "running"}})
        payload = {
            "channel": "email",
            "sender": email.get("sender", ""),
            "subject": email.get("subject", ""),
            "body": email.get("body_text", ""),
            "attachments": [],  # attachment bytes fetched separately if needed
        }
        ai = await analyze_message(user_id, payload)
        await db.emails.update_one(
            {"_id": email["_id"]},
            {"$set": {"analysis_status": "done",
                      "analyzed_at": datetime.now(timezone.utc),
                      "verdict": ai.get("verdict"),
                      "risk_score": ai.get("risk_score")}},
        )
        await notify_threat(user_id, ai.get("verdict", "safe"),
                            int(ai.get("risk_score", 0)),
                            email.get("subject", ""))
        return ai
    return asyncio.run(run())
