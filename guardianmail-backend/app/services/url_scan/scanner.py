"""Multi-provider URL threat intelligence with graceful degradation.

Each provider runs in parallel, with a hard 6s per-provider timeout. Missing
API keys skip that provider — the rest still run.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
import tldextract

from app.core.config import settings

TIMEOUT = 6.0


async def _gsb(client: httpx.AsyncClient, url: str) -> dict:
    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        return {"provider": "google_safe_browsing", "status": "skipped"}
    body = {
        "client": {"clientId": "guardianmail", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = await client.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_KEY}",
        json=body, timeout=TIMEOUT,
    )
    j = r.json() if r.status_code == 200 else {}
    return {"provider": "google_safe_browsing",
            "status": "flagged" if j.get("matches") else "clean",
            "matches": j.get("matches", [])}


async def _vt(client: httpx.AsyncClient, url: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"provider": "virustotal", "status": "skipped"}
    import base64
    u64 = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    r = await client.get(
        f"https://www.virustotal.com/api/v3/urls/{u64}",
        headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=TIMEOUT,
    )
    if r.status_code != 200:
        return {"provider": "virustotal", "status": "unknown"}
    stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
    return {"provider": "virustotal",
            "status": "flagged" if stats.get("malicious", 0) > 0 else "clean",
            "stats": stats}


async def _urlscan(client: httpx.AsyncClient, url: str) -> dict:
    r = await client.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"page.url:\"{url}\"", "size": 5}, timeout=TIMEOUT)
    if r.status_code != 200:
        return {"provider": "urlscan", "status": "unknown"}
    hits = r.json().get("results", [])
    return {"provider": "urlscan",
            "status": "flagged" if any(h.get("verdicts", {}).get("overall", {}).get("malicious") for h in hits) else "clean",
            "public_scan_count": len(hits)}


async def _rdap(client: httpx.AsyncClient, url: str) -> dict:
    dom = tldextract.extract(url).registered_domain
    if not dom:
        return {"provider": "rdap", "status": "unknown"}
    r = await client.get(f"https://rdap.org/domain/{dom}", timeout=TIMEOUT)
    if r.status_code != 200:
        return {"provider": "rdap", "status": "unknown"}
    j = r.json()
    reg = next((e["eventDate"] for e in j.get("events", []) if e.get("eventAction") == "registration"), None)
    return {"provider": "rdap", "status": "info", "registered_at": reg}


async def scan_one(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient() as c:
        results = await asyncio.gather(
            _gsb(c, url), _vt(c, url), _urlscan(c, url), _rdap(c, url),
            return_exceptions=True,
        )
    clean = [r for r in results if isinstance(r, dict)]
    flagged = any(r.get("status") == "flagged" for r in clean)
    return {"url": url, "flagged": flagged, "providers": clean}


async def scan_urls(urls: list[str]) -> dict:
    if not urls:
        return {"results": []}
    res = await asyncio.gather(*(scan_one(u) for u in urls[:20]))
    return {"results": res}
