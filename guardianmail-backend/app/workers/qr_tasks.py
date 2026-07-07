"""Celery task for asynchronous QR scanning."""
from __future__ import annotations

import asyncio
import base64

from app.database.mongodb import mongodb
from app.services.qr.decoder import decode_qr
from app.services.url_scan.scanner import scan_urls
from app.services.scoring.explainable import explain
from app.services.scoring.why import build as build_why
from app.services.tracking.forwards import record_forward
from app.services.tracking.device_link import link_artifact
from app.workers.celery_app import celery


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="qr.scan_image")
def scan_qr_image(user_id: str, image_b64: str, device_fingerprint: str | None = None) -> dict:
    async def run():
        await _bootstrap()
        raw = base64.b64decode(image_b64)
        codes = decode_qr(raw)
        urls = [c["payload"] for c in codes if c["is_url"]]
        intel = await scan_urls(urls) if urls else {"results": []}
        verdict = explain(url_intel=intel)
        why = build_why(verdict, artifact_kind="qr")
        primary = urls[0] if urls else (codes[0]["payload"] if codes else "")
        stats = await record_forward(kind="qr", key=primary, user_id=user_id,
                                     verdict=verdict["verdict"], risk_score=verdict["risk_score"])
        await link_artifact(user_id=user_id, device_fingerprint=device_fingerprint,
                            artifact_hash=stats["hash"], artifact_kind="qr",
                            verdict=verdict["verdict"], risk_score=verdict["risk_score"],
                            signals=verdict["signals"])
        return {"codes": codes, "url_intel": intel, "verdict": verdict, "why": why, "impact": stats}
    return asyncio.run(run())
