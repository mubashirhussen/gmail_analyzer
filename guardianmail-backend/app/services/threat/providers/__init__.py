"""Provider registry.

Adding a provider = adding one line here. Everything else (aggregation,
telemetry, caching) discovers providers through `ALL`.
"""
from __future__ import annotations

from app.services.threat.providers.abuseipdb import AbuseIpdbProvider
from app.services.threat.providers.base import BaseProvider, ProviderOutcome
from app.services.threat.providers.dns_ssl import DnsSslProvider
from app.services.threat.providers.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.threat.providers.phishtank import PhishTankProvider
from app.services.threat.providers.rdap_whois import RdapProvider
from app.services.threat.providers.urlhaus import UrlhausProvider
from app.services.threat.providers.urlscan import UrlscanProvider
from app.services.threat.providers.virustotal import VirusTotalProvider

ALL: tuple[BaseProvider, ...] = (
    GoogleSafeBrowsingProvider(),
    VirusTotalProvider(),
    UrlscanProvider(),
    PhishTankProvider(),
    UrlhausProvider(),
    RdapProvider(),
    AbuseIpdbProvider(),
    DnsSslProvider(),
)

BY_SLUG: dict[str, BaseProvider] = {p.slug: p for p in ALL}


def for_kind(kind: str) -> tuple[BaseProvider, ...]:
    return tuple(p for p in ALL if kind in p.kinds)


__all__ = ["ALL", "BY_SLUG", "for_kind", "BaseProvider", "ProviderOutcome"]
