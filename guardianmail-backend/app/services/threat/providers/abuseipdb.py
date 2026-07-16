"""AbuseIPDB — IP reputation & abuse-report aggregation."""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


class AbuseIpdbProvider(BaseProvider):
    slug = "abuseipdb"
    kinds = ("ip",)

    def enabled(self) -> bool:
        return bool(settings.ABUSEIPDB_KEY)

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": artifact_value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": settings.ABUSEIPDB_KEY, "Accept": "application/json"},
        )
        r.raise_for_status()
        j = (r.json() or {}).get("data") or {}
        score = float(j.get("abuseConfidenceScore") or 0)
        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict=verdict,
            score=score,
            normalized_score=score,  # already 0..100
            raw={
                "isp": j.get("isp"),
                "usageType": j.get("usageType"),
                "countryCode": j.get("countryCode"),
                "domain": j.get("domain"),
                "isTor": j.get("isTor"),
                "totalReports": j.get("totalReports"),
                "lastReportedAt": j.get("lastReportedAt"),
            },
            http_status=r.status_code,
        )
