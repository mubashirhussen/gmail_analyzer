"""RDAP / WHOIS domain intel (rdap.org — no key needed).

Focused on the four facts the aggregator actually needs: registration
date (→ age), expiration, registrar, and WHOIS privacy status.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


def _parse(dt: str | None) -> datetime | None:
    if not dt:
        return None
    try:
        return datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except ValueError:
        return None


class RdapProvider(BaseProvider):
    slug = "rdap"
    kinds = ("domain",)

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        r = await client.get(
            f"https://rdap.org/domain/{artifact_value}",
            headers={"Accept": "application/rdap+json"},
            follow_redirects=True,
        )
        if r.status_code == 404:
            return ProviderOutcome(
                self.slug, artifact_kind, artifact_value,
                status="ok", verdict="unknown",
                raw={"exists": False}, http_status=404,
            )
        r.raise_for_status()
        j = r.json() or {}
        registered = expiration = None
        for e in j.get("events", []) or []:
            act = (e.get("eventAction") or "").lower()
            if act == "registration":
                registered = _parse(e.get("eventDate"))
            elif act in ("expiration", "expiry"):
                expiration = _parse(e.get("eventDate"))
        registrar = None
        for ent in j.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for arr in ent.get("vcardArray", [[], []])[1:]:
                    for item in arr:
                        if item and item[0] == "fn":
                            registrar = item[3]
                            break
        privacy = any(
            "privacy" in (ent.get("remarks", [{}])[0].get("title", "") or "").lower()
            for ent in j.get("entities", []) or []
        )
        age_days = None
        if registered:
            age_days = int((datetime.now(timezone.utc) - registered).days)
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict="unknown",
            raw={
                "exists": True,
                "registered_at": registered.isoformat() if registered else None,
                "expires_at": expiration.isoformat() if expiration else None,
                "registrar": registrar,
                "whois_privacy": privacy,
                "age_days": age_days,
                "status": j.get("status"),
            },
            http_status=r.status_code,
        )
