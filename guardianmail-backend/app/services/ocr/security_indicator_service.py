"""Security-indicator extraction — post-processing on already-parsed data.

Consumes the extracted text plus URLs/emails/QR results and produces
categorised human-readable indicators for the report + AI grounding.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models.ocr_report import (
    ExtractedPatterns, QRResult, SecurityIndicators,
)
from app.services.ocr.config import (
    COMMON_BRANDS, CREDENTIAL_PHRASES, INVOICE_PHRASES, KNOWN_SHORTENERS,
    PAYMENT_PHRASES, URGENT_PHRASES,
)

_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "rn": "m", "vv": "w",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalise(domain: str) -> str:
    host = domain.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    for k, v in _HOMOGLYPHS.items():
        host = host.replace(k, v)
    return host


def _brand_root(host: str) -> str:
    parts = host.split(".")
    return parts[-2] if len(parts) >= 2 else host


def _find_phrases(text_lower: str, phrases: list[str]) -> list[str]:
    return sorted({p for p in phrases if p in text_lower})


def build(text: str, patterns: ExtractedPatterns, qrs: list[QRResult]) -> SecurityIndicators:
    text_lower = (text or "").lower()

    shortened: list[str] = []
    suspicious: list[str] = []
    typosquats: list[str] = []
    brand_mentions: set[str] = set()

    all_urls = list(patterns.urls) + [q.payload for q in qrs if q.is_url]
    for u in all_urls:
        try:
            host = urlparse(u).hostname or ""
        except Exception:
            continue
        if not host:
            continue
        h = _normalise(host)
        if any(h == s or h.endswith("." + s) for s in KNOWN_SHORTENERS):
            shortened.append(u)
        root = _brand_root(h)
        # brand mentions
        for brand in COMMON_BRANDS:
            if brand in h.split("."):
                brand_mentions.add(brand)
            elif brand in root and root != brand:
                # e.g. "paypal-login" → mention + typosquat
                brand_mentions.add(brand)
                typosquats.append(u)
            else:
                dist = _levenshtein(root, brand)
                if 0 < dist <= 2 and len(brand) >= 5:
                    typosquats.append(u)
                    brand_mentions.add(brand)
        # generic suspicion: raw IP host, punycode, many hyphens
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", h) or h.startswith("xn--") or h.count("-") >= 3:
            suspicious.append(u)

    return SecurityIndicators(
        suspicious_urls=sorted(set(suspicious))[:50],
        shortened_urls=sorted(set(shortened))[:50],
        typosquat_candidates=sorted(set(typosquats))[:50],
        embedded_emails=list(patterns.emails)[:50],
        urgent_language=_find_phrases(text_lower, URGENT_PHRASES),
        credential_prompts=_find_phrases(text_lower, CREDENTIAL_PHRASES),
        payment_prompts=_find_phrases(text_lower, PAYMENT_PHRASES),
        invoice_signals=_find_phrases(text_lower, INVOICE_PHRASES),
        brand_mentions=sorted(brand_mentions),
    )
