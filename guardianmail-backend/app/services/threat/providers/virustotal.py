"""VirusTotal v3 — URL, domain, file-hash intel."""
from __future__ import annotations

import base64

import httpx

from app.core.config import settings
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class VirusTotalProvider(BaseProvider):
    slug = "virustotal"
    kinds = ("url", "domain", "file_hash")

    def enabled(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY)

    def _endpoint(self, kind: ArtifactKind, value: str) -> str:
        if kind == "url":
            uid = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
            return f"https://www.virustotal.com/api/v3/urls/{uid}"
        if kind == "domain":
            return f"https://www.virustotal.com/api/v3/domains/{value}"
        return f"https://www.virustotal.com/api/v3/files/{value}"

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        r = await client.get(
            self._endpoint(artifact_kind, artifact_value),
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"},
        )
        if r.status_code == 404:
            return ProviderOutcome(
                self.slug, artifact_kind, artifact_value,
                status="ok", verdict="unknown", http_status=404,
            )
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {}) or {}
        stats = data.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious") or 0)
        susp = int(stats.get("suspicious") or 0)
        total = sum(int(v or 0) for v in stats.values()) or 1
        if mal >= 3:
            verdict, score = "malicious", min(100.0, 40 + (mal / total) * 100)
        elif mal >= 1 or susp >= 2:
            verdict, score = "suspicious", 30 + (susp / total) * 40
        else:
            verdict, score = "clean", 0.0
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict=verdict,
            score=float(mal),
            normalized_score=float(score),
            raw={
                "stats": stats,
                "reputation": data.get("reputation"),
                "categories": data.get("categories"),
                "last_analysis_date": data.get("last_analysis_date"),
            },
            http_status=r.status_code,
        )
