"""URLHaus (abuse.ch) — free malware-URL feed. No API key required."""
from __future__ import annotations

import httpx

from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class UrlhausProvider(BaseProvider):
    slug = "urlhaus"
    kinds = ("url", "domain")

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        endpoint = (
            "https://urlhaus-api.abuse.ch/v1/url/"
            if artifact_kind == "url"
            else "https://urlhaus-api.abuse.ch/v1/host/"
        )
        field = "url" if artifact_kind == "url" else "host"
        r = await client.post(endpoint, data={field: artifact_value})
        r.raise_for_status()
        j = r.json() or {}
        status = (j.get("query_status") or "").lower()
        if status == "ok":
            threat = j.get("threat") or ""
            verdict, score = "malicious", 92.0 if threat else 80.0
        elif status == "no_results":
            verdict, score = "clean", 0.0
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
                "query_status": status,
                "threat": j.get("threat"),
                "tags": j.get("tags"),
                "url_count": j.get("url_count"),
            },
            http_status=r.status_code,
        )
