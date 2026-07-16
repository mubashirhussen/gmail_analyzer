"""Threat orchestrator — parallel provider execution + correlation.

Additive facade. Does NOT replace `services/url_scan/scanner.scan_urls`
or the existing scoring pipeline; other modules may adopt it opportunistically.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Iterable

import httpx

from app.database.redis import get_redis

from . import heuristics
from .correlation import correlate
from .providers import DEFAULT_PROVIDERS, Provider, TIMEOUT
from .schemas import NormalizedProviderResult, ThreatVerdict

CACHE_PREFIX = "ti:v1"
CACHE_TTL_S = 60 * 60 * 6   # 6h for URL reputation
NEG_CACHE_TTL_S = 60 * 30   # 30m for clean verdicts


async def _cached_scan(url: str, providers: dict[str, Provider]) -> list[NormalizedProviderResult]:
    try:
        r = get_redis()
        raw = await r.get(f"{CACHE_PREFIX}:{url}")
        if raw:
            data = json.loads(raw)
            return [NormalizedProviderResult(**d) for d in data]
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        tasks = [
            asyncio.wait_for(fn(client, url), timeout=TIMEOUT + 1)
            for fn in providers.values()
        ]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

    results: list[NormalizedProviderResult] = []
    for name, res in zip(providers.keys(), gathered):
        if isinstance(res, NormalizedProviderResult):
            results.append(res)
        elif isinstance(res, asyncio.TimeoutError):
            results.append(NormalizedProviderResult(
                provider=name, status="timeout",
                error="provider timeout",
            ))
        else:
            results.append(NormalizedProviderResult(
                provider=name, status="error", error=str(res),
            ))

    try:
        r = get_redis()
        payload = json.dumps([x.to_dict() for x in results])
        ttl = CACHE_TTL_S if any(x.malicious for x in results) else NEG_CACHE_TTL_S
        await r.setex(f"{CACHE_PREFIX}:{url}", ttl, payload)
    except Exception:
        pass

    return results


async def analyze_url(
    url: str,
    providers: dict[str, Provider] | None = None,
) -> ThreatVerdict:
    """Analyze a single URL end-to-end."""
    provs = providers or DEFAULT_PROVIDERS
    results = await _cached_scan(url, provs)
    inds = heuristics.analyze_url(url)
    return correlate(results, inds, has_urls=True)


async def analyze_artifact(
    *,
    urls: Iterable[str] = (),
    text: str = "",
    attachments: Iterable[dict[str, Any]] = (),
    email_auth: dict[str, Any] | None = None,
    providers: dict[str, Provider] | None = None,
) -> ThreatVerdict:
    """Full-artifact analysis: URLs + text + attachments + email auth."""
    provs = providers or DEFAULT_PROVIDERS
    urls_list = list(urls)[:20]
    atts_list = list(attachments)

    per_url = await asyncio.gather(
        *(_cached_scan(u, provs) for u in urls_list)
    ) if urls_list else []

    provider_results: list[NormalizedProviderResult] = [
        r for group in per_url for r in group
    ]

    indicators: list[dict[str, Any]] = []
    for u in urls_list:
        indicators.extend(heuristics.analyze_url(u))
    indicators.extend(heuristics.analyze_text(text))
    for a in atts_list:
        indicators.extend(heuristics.analyze_attachment(a))
    indicators.extend(heuristics.analyze_email_auth(email_auth))

    return correlate(
        provider_results, indicators,
        has_urls=bool(urls_list), has_attachments=bool(atts_list),
    )
