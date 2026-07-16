"""URLScan.io — public scan history lookup (no submission)."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class UrlscanProvider(BaseProvider):
    slug = "urlscan"
    kinds = ("url", "domain")

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        headers = {}
        if settings.URLSCAN_API_KEY:
            headers["API-Key"] = settings.URLSCAN_API_KEY
        query = (
            f'page.url:"{artifact_value}"' if artifact_kind == "url"
            else f'page.domain:"{artifact_value}"'
        )
        r = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 10},
            headers=headers,
        )
        r.raise_for_status()
        j = r.json()
        results = j.get("results", []) or []
        malicious = [h for h in results if h.get("verdicts", {}).get("overall", {}).get("malicious")]
        if malicious:
            verdict, score = "malicious", 90.0
        elif results:
            verdict, score = "unknown", 5.0
        else:
            verdict, score = "unknown", 0.0
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict=verdict,
            normalized_score=score,
            raw={
                "total": len(results),
                "malicious": len(malicious),
                "sample": [
                    {"uuid": h.get("_id"), "verdicts": h.get("verdicts")}
                    for h in results[:3]
                ],
            },
            http_status=r.status_code,
        )
