"""PhishTank lookup — public feed of confirmed phishing URLs."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class PhishTankProvider(BaseProvider):
    slug = "phishtank"
    kinds = ("url",)

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        data = {"url": artifact_value, "format": "json"}
        if settings.PHISHTANK_APP_KEY:
            data["app_key"] = settings.PHISHTANK_APP_KEY
        r = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=data,
            headers={"User-Agent": "guardianmail-threat-engine/1.0"},
        )
        r.raise_for_status()
        try:
            j = r.json()
        except ValueError:
            return ProviderOutcome(
                self.slug, artifact_kind, artifact_value,
                status="error", error_code="bad_json",
            )
        results = (j.get("results") or {})
        in_db = bool(results.get("in_database"))
        verified = bool(results.get("verified"))
        valid = bool(results.get("valid"))
        if in_db and verified and valid:
            verdict, score = "malicious", 92.0
        elif in_db:
            verdict, score = "suspicious", 55.0
        else:
            verdict, score = "clean", 0.0
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict=verdict,
            normalized_score=score,
            raw=results,
            http_status=r.status_code,
        )
