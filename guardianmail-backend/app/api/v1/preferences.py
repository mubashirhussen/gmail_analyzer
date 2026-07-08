"""User notification preferences: channels + threat thresholds.

Applied by `notify_user()` before dispatching any alert.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/preferences", tags=["preferences"])

VERDICT_RANK = {"safe": 0, "suspicious": 1, "phishing": 2, "fraud": 3}


class ChannelPrefs(BaseModel):
    in_app: bool = True
    email: bool = True
    webhook: bool = False


class PreferencesIn(BaseModel):
    channels: ChannelPrefs = Field(default_factory=ChannelPrefs)
    min_verdict: str = Field("suspicious", pattern="^(safe|suspicious|phishing|fraud)$")
    min_risk_score: int = Field(50, ge=0, le=100)
    webhook_url: HttpUrl | None = None
    webhook_secret: str | None = None
    email_to: str | None = None


async def get_preferences(user_id: str) -> dict:
    db = get_db()
    row = await db.notification_preferences.find_one({"_id": user_id})
    if not row:
        row = {
            "_id": user_id,
            "channels": ChannelPrefs().model_dump(),
            "min_verdict": "suspicious",
            "min_risk_score": 50,
            "webhook_url": None,
            "webhook_secret": None,
            "email_to": None,
        }
    return row


def should_notify(prefs: dict, verdict: str, risk_score: int) -> bool:
    if VERDICT_RANK.get(verdict, 0) < VERDICT_RANK.get(prefs.get("min_verdict", "suspicious"), 1):
        return False
    if int(risk_score) < int(prefs.get("min_risk_score", 50)):
        return False
    return True


@router.get("")
async def read_prefs(user=Depends(require_user)):
    return await get_preferences(user["sub"])


@router.put("")
async def update_prefs(body: PreferencesIn, user=Depends(require_user), db=Depends(get_db)):
    if body.channels.webhook and not body.webhook_url:
        raise HTTPException(400, "webhook channel enabled but no webhook_url configured")
    if body.channels.email and not body.email_to:
        raise HTTPException(400, "email channel enabled but no email_to configured")
    doc = {
        "_id": user["sub"],
        "channels": body.channels.model_dump(),
        "min_verdict": body.min_verdict,
        "min_risk_score": body.min_risk_score,
        "webhook_url": str(body.webhook_url) if body.webhook_url else None,
        "webhook_secret": body.webhook_secret,
        "email_to": body.email_to,
        "updated_at": datetime.now(timezone.utc),
    }
    await db.notification_preferences.replace_one({"_id": user["sub"]}, doc, upsert=True)
    return doc
