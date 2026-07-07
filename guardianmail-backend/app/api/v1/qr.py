"""QR-code scanning API — decode → threat-intel → explainable verdict."""
from __future__ import annotations

import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import require_user
from app.database.mongodb import get_db
from app.services.qr.decoder import decode_qr
from app.services.url_scan.scanner import scan_urls
from app.services.scoring.explainable import explain
from app.services.scoring.why import build as build_why
from app.services.tracking.forwards import record_forward
from app.services.tracking.device_link import link_artifact

router = APIRouter(prefix="/qr", tags=["qr"])


class QRIn(BaseModel):
    image_b64: str = Field(..., description="base64-encoded PNG/JPEG image")
    device_fingerprint: str | None = None


@router.post("/scan")
async def scan_qr(body: QRIn, user=Depends(require_user), db=Depends(get_db)):
    try:
        raw = base64.b64decode(body.image_b64)
    except Exception as e:
        raise HTTPException(400, f"invalid base64: {e}") from e

    codes = decode_qr(raw)
    if not codes:
        raise HTTPException(422, "no QR code detected in image")

    urls = [c["payload"] for c in codes if c["is_url"]]
    intel = await scan_urls(urls) if urls else {"results": []}

    verdict = explain(url_intel=intel, community_report_count=0)
    why = build_why(verdict, artifact_kind="qr")

    # tracking + persistence
    primary_key = urls[0] if urls else codes[0]["payload"]
    stats = await record_forward(kind="qr", key=primary_key, user_id=user["sub"],
                                 verdict=verdict["verdict"], risk_score=verdict["risk_score"])
    await link_artifact(user_id=user["sub"], device_fingerprint=body.device_fingerprint,
                        artifact_hash=stats["hash"], artifact_kind="qr",
                        verdict=verdict["verdict"], risk_score=verdict["risk_score"],
                        signals=verdict["signals"])

    await db.threats.insert_one({
        "user_id": user["sub"], "channel": "qr",
        "qr_codes": codes, "url_intel": intel,
        "verdict": verdict["verdict"], "risk_score": verdict["risk_score"],
        "signals": verdict["signals"],
        "created_at": datetime.now(timezone.utc),
    })

    return {
        "codes": codes,
        "url_intel": intel,
        "verdict": verdict,
        "why": why,
        "impact": stats,
    }
