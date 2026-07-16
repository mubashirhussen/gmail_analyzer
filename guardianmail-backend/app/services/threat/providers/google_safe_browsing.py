"""Google Safe Browsing v4 — threatMatches:find."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class GoogleSafeBrowsingProvider(BaseProvider):
    slug = "google_safe_browsing"
    kinds = ("url",)

    def enabled(self) -> bool:
        return bool(settings.GOOGLE_SAFE_BROWSING_KEY)

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        body = {
            "client": {"clientId": "guardianmail", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": artifact_value}],
            },
        }
        r = await client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": settings.GOOGLE_SAFE_BROWSING_KEY},
            json=body,
        )
        r.raise_for_status()
        j = r.json()
        matches = j.get("matches") or []
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict="malicious" if matches else "clean",
            normalized_score=95.0 if matches else 0.0,
            raw={"matches": matches[:5]},
            http_status=r.status_code,
        )
