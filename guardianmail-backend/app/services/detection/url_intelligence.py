"""URLIntelligenceService — shorteners, IP URLs, obfuscation, credential forms.

Structural URL heuristics only. Live URL scanning stays owned by Module
15 / provider integrations.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

from app.services.detection.domain_intelligence import domain_intelligence_service

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id",
}
_CRED_HINTS = re.compile(
    r"(login|signin|verify|account|secure|update|reset|confirm|invoice|"
    r"payment|wallet|billing|password)",
    re.I,
)


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "")) or ":" in (host or "")


class URLIntelligenceService:
    def analyze_one(self, url: str) -> dict:
        try:
            decoded = unquote(url)
            parsed = urlparse(decoded)
        except Exception:
            return {"url": url, "score": 30, "flags": ["unparsable_url"]}

        host = (parsed.hostname or "").lower()
        flags: list[str] = []
        score = 0.0

        if _is_ip(host):
            flags.append("ip_url")
            score += 30
        if host in _SHORTENERS:
            flags.append("shortener")
            score += 20
        if "%" in url or "\\x" in url:
            flags.append("encoded_url")
            score += 10
        if parsed.username or parsed.password:
            flags.append("userinfo_in_url")
            score += 25
        if parsed.port and parsed.port not in (80, 443):
            flags.append(f"nonstandard_port:{parsed.port}")
            score += 10
        if _CRED_HINTS.search(parsed.path or "") or _CRED_HINTS.search(parsed.query or ""):
            flags.append("credential_keywords")
            score += 15
        # Open-redirect abuse: nested URL in query.
        if re.search(r"(https?%3a|https?://)", (parsed.query or ""), re.I):
            flags.append("nested_url_in_query")
            score += 15

        dom = domain_intelligence_service.analyze(host)
        if dom.get("flags"):
            score += dom["score"] * 0.5
            flags.extend(f"domain:{f}" for f in dom["flags"])

        return {
            "url": url,
            "host": host,
            "flags": flags,
            "score": min(80.0, score),
            "domain": dom,
        }

    def analyze(self, urls: list[str] | None) -> list[dict]:
        return [self.analyze_one(u) for u in (urls or []) if u]


url_intelligence_service = URLIntelligenceService()
