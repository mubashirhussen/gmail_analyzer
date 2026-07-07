"""Webhook endpoint — receives forwarded email content from the frontend or
mail-forward integrations, runs the full pipeline, and returns the risk score
plus recommended actions.
"""
from __future__ import annotations

import hmac
import hashlib
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.config import settings
from app.database.mongodb import get_db
from app.services.phishing.pipeline import analyze_message
from app.services.scoring.why import build as build_why
from app.services.tracking.forwards import record_forward
from app.services.tracking.device_link import link_artifact

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class ForwardIn(BaseModel):
    user_id: str = Field(..., description="Owner of the artifact")
    channel: str = Field("email", pattern="^(email|social)$")
    sender: str = ""
    subject: str = ""
    body: str = ""
    attachments: list[dict] = []
    device_fingerprint: str | None = None


def _verify_signature(raw: bytes, signature: str | None) -> None:
    secret = getattr(settings, "WEBHOOK_SECRET", None) or ""
    if not secret:
        return  # dev mode
    if not signature:
        raise HTTPException(401, "missing signature")
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "bad signature")


@router.post("/email-forward")
async def email_forward(
    request: Request,
    x_signature: str | None = Header(default=None, alias="X-Signature"),
    db=Depends(get_db),
):
    raw = await request.body()
    _verify_signature(raw, x_signature)
    body = ForwardIn.model_validate_json(raw)

    ai = await analyze_message(body.user_id, body.model_dump())

    # explainability + tracking
    verdict = {
        "verdict": ai.get("verdict"),
        "risk_score": int(ai.get("risk_score", 0)),
        "confidence": int(ai.get("confidence", 50)),
        "signals": ai.get("signals", []) or [
            {"category": i.get("category", "generic"),
             "weight": 10, "severity": i.get("severity", "medium"),
             "detail": i.get("detail", ""), "evidence": {}}
            for i in ai.get("indicators", [])
        ],
    }
    why = build_why(verdict, artifact_kind=body.channel)
    stats = await record_forward(
        kind=body.channel,
        key=f"{body.sender}|{body.subject}",
        user_id=body.user_id,
        verdict=verdict["verdict"] or "safe",
        risk_score=verdict["risk_score"],
    )
    await link_artifact(user_id=body.user_id, device_fingerprint=body.device_fingerprint,
                        artifact_hash=stats["hash"], artifact_kind=body.channel,
                        verdict=verdict["verdict"] or "safe",
                        risk_score=verdict["risk_score"], signals=verdict["signals"])

    return {
        "verdict": verdict,
        "why": why,
        "impact": stats,
        "recommended_actions": why["next_steps"],
    }


@router.get("/impact/{kind}")
async def impact_lookup(kind: str, key: str):
    """Public read-only: how many times a link/mail/QR has been forwarded and users impacted."""
    from app.services.tracking.forwards import get_stats
    return await get_stats(kind, key)
