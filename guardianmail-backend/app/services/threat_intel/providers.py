"""Pluggable provider adapters.

Each provider is an async callable `(client, url) -> NormalizedProviderResult`.
Providers self-skip when their API key is missing so the orchestrator keeps
running with partial evidence.

The reputation weight of each provider drives the correlation confidence.
"""
from __future__ import annotations

import asyncio
import base64
import time
from typing import Awaitable, Callable

import httpx
import tldextract

from app.core.config import settings

from .schemas import NormalizedProviderResult

Provider = Callable[[httpx.AsyncClient, str], Awaitable[NormalizedProviderResult]]

TIMEOUT = 6.0

# Provider reputation weight (0–1). Multi-source agreement is what raises
# overall confidence; weight only breaks ties when a single provider fires.
PROVIDER_WEIGHTS: dict[str, float] = {
    "google_safe_browsing": 0.95,
    "virustotal": 0.90,
    "urlscan": 0.75,
    "abuseipdb": 0.80,
    "openphish": 0.85,
    "phishtank": 0.85,
    "urlhaus": 0.85,
    "spamhaus": 0.80,
    "talos": 0.75,
    "otx": 0.70,
    "rdap": 0.30,   # informational
    "whois": 0.30,  # informational
}


def _ts_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


# ---- Google Safe Browsing ---------------------------------------------
async def gsb(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    key = getattr(settings, "GOOGLE_SAFE_BROWSING_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="google_safe_browsing", status="skipped")
    body = {
        "client": {"clientId": "guardianmail", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                             "UNWANTED_SOFTWARE",
                             "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body, timeout=TIMEOUT,
        )
        j = r.json() if r.status_code == 200 else {}
        matches = j.get("matches", [])
        return NormalizedProviderResult(
            provider="google_safe_browsing", status="ok",
            verdict="malicious" if matches else "safe",
            malicious=bool(matches), safe=not matches,
            confidence=0.95 if matches else 0.6,
            threat_types=[m.get("threatType") for m in matches if m.get("threatType")],
            detection_reason=matches[0].get("threatType") if matches else None,
            raw=j, latency_ms=_ts_ms(start),
        )
    except Exception as e:  # timeout / network
        return NormalizedProviderResult(
            provider="google_safe_browsing", status="error",
            error=str(e), latency_ms=_ts_ms(start),
        )


# ---- VirusTotal --------------------------------------------------------
async def virustotal(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="virustotal", status="skipped")
    try:
        u64 = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        r = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{u64}",
            headers={"x-apikey": key}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="virustotal", status="unknown",
                latency_ms=_ts_ms(start),
            )
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        conf = min(1.0, (mal * 2 + susp) / max(total, 10))
        return NormalizedProviderResult(
            provider="virustotal", status="ok",
            verdict="malicious" if mal else ("suspicious" if susp else "safe"),
            malicious=mal > 0, suspicious=susp > 0, safe=(mal + susp) == 0,
            confidence=conf,
            detection_reason=f"{mal} malicious / {susp} suspicious of {total} engines",
            raw={"stats": stats}, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="virustotal", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- URLScan.io --------------------------------------------------------
async def urlscan(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    try:
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{url}"', "size": 5},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="urlscan", status="unknown",
                latency_ms=_ts_ms(start),
            )
        hits = r.json().get("results", [])
        mal = any(
            h.get("verdicts", {}).get("overall", {}).get("malicious")
            for h in hits
        )
        return NormalizedProviderResult(
            provider="urlscan", status="ok",
            verdict="malicious" if mal else "safe",
            malicious=mal, safe=not mal,
            confidence=0.85 if mal else 0.4,
            detection_reason=f"{len(hits)} public scans" if hits else None,
            raw={"count": len(hits)}, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="urlscan", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- URLHaus (abuse.ch) — no key required -----------------------------
async def urlhaus(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="urlhaus", status="unknown",
                latency_ms=_ts_ms(start),
            )
        j = r.json()
        status = j.get("query_status")
        if status == "ok":
            threat = j.get("threat")
            return NormalizedProviderResult(
                provider="urlhaus", status="ok",
                verdict="malicious", malicious=True, confidence=0.9,
                threat_types=[threat] if threat else [],
                detection_reason=f"URLHaus: {threat}",
                reference_url=j.get("urlhaus_reference"),
                raw=j, latency_ms=_ts_ms(start),
            )
        return NormalizedProviderResult(
            provider="urlhaus", status="ok",
            verdict="safe", safe=True, confidence=0.5,
            latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="urlhaus", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- OpenPhish (public feed lookup) -----------------------------------
async def openphish(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    # Free feed is a downloadable list; keep a lightweight adapter that
    # marks as skipped unless an API key is configured for the paid feed.
    start = time.perf_counter()
    key = getattr(settings, "OPENPHISH_API_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="openphish", status="skipped")
    try:
        r = await client.get(
            "https://openphish.com/feed.txt", timeout=TIMEOUT,
            headers={"Authorization": f"Bearer {key}"},
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="openphish", status="unknown",
                latency_ms=_ts_ms(start),
            )
        hit = url.strip() in r.text
        return NormalizedProviderResult(
            provider="openphish", status="ok",
            verdict="malicious" if hit else "safe",
            malicious=hit, safe=not hit,
            confidence=0.9 if hit else 0.4,
            detection_reason="OpenPhish feed match" if hit else None,
            latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="openphish", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- PhishTank ---------------------------------------------------------
async def phishtank(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    key = getattr(settings, "PHISHTANK_API_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="phishtank", status="skipped")
    try:
        r = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": key},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="phishtank", status="unknown",
                latency_ms=_ts_ms(start),
            )
        j = r.json()
        in_db = j.get("results", {}).get("in_database")
        verified = j.get("results", {}).get("verified")
        mal = bool(in_db and verified)
        return NormalizedProviderResult(
            provider="phishtank", status="ok",
            verdict="malicious" if mal else "safe",
            malicious=mal, safe=not mal,
            confidence=0.9 if mal else 0.4,
            reference_url=j.get("results", {}).get("phish_detail_page"),
            raw=j, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="phishtank", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- AbuseIPDB (per-URL host lookup) ----------------------------------
async def abuseipdb(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    key = getattr(settings, "ABUSEIPDB_API_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="abuseipdb", status="skipped")
    try:
        host = tldextract.extract(url).registered_domain
        if not host:
            return NormalizedProviderResult(
                provider="abuseipdb", status="unknown",
                latency_ms=_ts_ms(start),
            )
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": host, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="abuseipdb", status="unknown",
                latency_ms=_ts_ms(start),
            )
        j = r.json().get("data", {})
        score = int(j.get("abuseConfidenceScore", 0))
        return NormalizedProviderResult(
            provider="abuseipdb", status="ok",
            verdict="malicious" if score >= 75 else ("suspicious" if score >= 30 else "safe"),
            malicious=score >= 75, suspicious=30 <= score < 75, safe=score < 30,
            confidence=min(1.0, score / 100.0),
            detection_reason=f"AbuseIPDB confidence {score}",
            raw=j, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="abuseipdb", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- AlienVault OTX ---------------------------------------------------
async def otx(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    key = getattr(settings, "OTX_API_KEY", None)
    if not key:
        return NormalizedProviderResult(provider="otx", status="skipped")
    try:
        dom = tldextract.extract(url).registered_domain
        if not dom:
            return NormalizedProviderResult(provider="otx", status="unknown")
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/general",
            headers={"X-OTX-API-KEY": key}, timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="otx", status="unknown", latency_ms=_ts_ms(start),
            )
        j = r.json()
        pulses = j.get("pulse_info", {}).get("count", 0)
        mal = pulses > 0
        return NormalizedProviderResult(
            provider="otx", status="ok",
            verdict="suspicious" if mal else "safe",
            suspicious=mal, safe=not mal,
            confidence=min(1.0, pulses / 5) if mal else 0.4,
            detection_reason=f"OTX pulses: {pulses}" if mal else None,
            raw={"pulses": pulses}, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="otx", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


# ---- RDAP (WHOIS-lite, no key) ----------------------------------------
async def rdap(client: httpx.AsyncClient, url: str) -> NormalizedProviderResult:
    start = time.perf_counter()
    try:
        dom = tldextract.extract(url).registered_domain
        if not dom:
            return NormalizedProviderResult(
                provider="rdap", status="unknown",
                latency_ms=_ts_ms(start),
            )
        r = await client.get(f"https://rdap.org/domain/{dom}", timeout=TIMEOUT)
        if r.status_code != 200:
            return NormalizedProviderResult(
                provider="rdap", status="unknown",
                latency_ms=_ts_ms(start),
            )
        j = r.json()
        reg = next((e["eventDate"] for e in j.get("events", [])
                    if e.get("eventAction") == "registration"), None)
        return NormalizedProviderResult(
            provider="rdap", status="ok", verdict="unknown",
            confidence=0.3,
            detection_reason=f"registered {reg}" if reg else None,
            raw={"registered_at": reg}, latency_ms=_ts_ms(start),
        )
    except Exception as e:
        return NormalizedProviderResult(
            provider="rdap", status="error", error=str(e),
            latency_ms=_ts_ms(start),
        )


DEFAULT_PROVIDERS: dict[str, Provider] = {
    "google_safe_browsing": gsb,
    "virustotal": virustotal,
    "urlscan": urlscan,
    "urlhaus": urlhaus,
    "openphish": openphish,
    "phishtank": phishtank,
    "abuseipdb": abuseipdb,
    "otx": otx,
    "rdap": rdap,
}


def registered_providers() -> list[str]:
    return list(DEFAULT_PROVIDERS.keys())
