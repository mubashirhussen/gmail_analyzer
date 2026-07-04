"""Gemini wrapper — returns strict JSON, degrades to heuristic if key missing."""
from __future__ import annotations

import json
from typing import Any

import google.generativeai as genai

from app.core.config import settings

if settings.GEMINI_API_KEY:
    genai.configure(api_key=settings.GEMINI_API_KEY)


async def gemini_json(system: str, user: Any, model: str = "gemini-1.5-flash") -> dict:
    if not settings.GEMINI_API_KEY:
        return {"verdict": "suspicious", "risk_score": 50, "confidence": 30,
                "summary": "AI key missing — heuristic fallback.", "indicators": [], "recommendations": []}
    m = genai.GenerativeModel(model, system_instruction=system)
    prompt = user if isinstance(user, str) else json.dumps(user, default=str)[:60_000]
    r = await m.generate_content_async(prompt, generation_config={"response_mime_type": "application/json"})
    try:
        return json.loads(r.text)
    except json.JSONDecodeError:
        return {"verdict": "suspicious", "risk_score": 55, "summary": r.text[:400], "indicators": [], "recommendations": []}
