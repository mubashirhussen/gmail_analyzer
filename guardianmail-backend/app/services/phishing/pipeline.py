"""End-to-end phishing analysis pipeline.

Event-driven fan-out — each stage is independent and returns a partial signal
dict. The final AI stage fuses everything into a verdict + risk score.
"""
from __future__ import annotations

import asyncio
import base64
import re
from datetime import datetime, timezone
from typing import Any

from app.database.mongodb import get_db
from app.services.ai.gemini import gemini_json
from app.services.ocr.ocr import extract_text
from app.services.url_scan.scanner import scan_urls
from app.services.security.email_auth import spf_dkim_dmarc

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)


async def _ocr_attachments(atts: list[dict]) -> list[dict]:
    async def one(a: dict) -> dict:
        raw = base64.b64decode(a.get("data_b64", ""))
        text = await extract_text(raw, mime=a.get("mime", ""))
        return {"name": a.get("name"), "mime": a.get("mime"), "text": text[:20_000]}
    return await asyncio.gather(*(one(a) for a in atts))


def _extract_urls(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,);]")
        if u not in seen:
            seen.add(u); out.append(u)
    return out[:20]


async def analyze_message(user_id: str, payload: dict[str, Any]) -> dict:
    body = payload.get("body", "")
    sender = payload.get("sender", "")
    subject = payload.get("subject", "")
    channel = payload.get("channel", "email")

    ocr_task = _ocr_attachments(payload.get("attachments", []))
    auth_task = spf_dkim_dmarc(sender) if channel == "email" else asyncio.sleep(0, result=None)
    ocr_results, auth = await asyncio.gather(ocr_task, auth_task)

    full_text = "\n".join([body] + [o["text"] for o in ocr_results if o.get("text")])
    urls = _extract_urls(full_text)
    intel = await scan_urls(urls) if urls else {"results": []}

    # AI fusion
    system = (
        "You are GuardianMail, an elite phishing/fraud analyst. "
        "Given the message + OCR text + email auth results + per-URL threat intel, "
        "return JSON {verdict, risk_score, confidence, attack_category, summary, "
        "indicators:[{category,severity,detail}], recommendations:[str]}. "
        "verdict ∈ safe|suspicious|phishing|fraud."
    )
    ai = await gemini_json(system=system, user={
        "channel": channel, "sender": sender, "subject": subject,
        "body": body[:12_000],
        "ocr": ocr_results,
        "auth": auth,
        "url_intel": intel,
    })

    # persist
    db = get_db()
    doc = {
        "user_id": user_id, "channel": channel, "sender": sender, "subject": subject,
        "url_intel": intel, "email_auth": auth, "ocr": ocr_results,
        "verdict": ai.get("verdict"), "risk_score": ai.get("risk_score"),
        "attack_category": ai.get("attack_category"),
        "created_at": datetime.now(timezone.utc),
    }
    await db.threats.insert_one(doc)
    return ai
