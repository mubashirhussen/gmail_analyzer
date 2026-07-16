"""URL analysis — extracts and classifies URL-level risk signals.

The service consumes provider outcomes plus intrinsic URL features
(scheme, TLD, IDN, typosquat, obfuscation) and returns a set of
`Indicator` records the aggregator translates into scores.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from app.services.threat.config import (
    DISPOSABLE_DOMAINS,
    RISKY_TLDS,
)
from app.services.threat.normalizer import (
    is_idn,
    registered_domain,
    subdomain_of,
    tld_of,
)
from app.services.threat.providers.base import ProviderOutcome
from app.services.threat.typosquat import looks_like_brand


@dataclass(slots=True)
class UrlIndicator:
    category: str
    severity: str
    detail: str
    url: str
    evidence: dict


_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "shorte.st", "s.id", "rb.gy",
    "lnkd.in", "bit.do",
}

_OBFUSCATION_RE = re.compile(r"(?:%[0-9a-f]{2}){3,}", re.IGNORECASE)
_MANY_SUBDOMAINS = 4


class UrlAnalysisService:
    def analyze(
        self,
        urls: Iterable[str],
        provider_outcomes: list[ProviderOutcome],
    ) -> list[UrlIndicator]:
        indicators: list[UrlIndicator] = []
        by_url: dict[str, list[ProviderOutcome]] = {}
        for o in provider_outcomes:
            if o.artifact_kind != "url":
                continue
            by_url.setdefault(o.artifact_value, []).append(o)

        for url in urls:
            indicators.extend(self._intrinsic(url))
            indicators.extend(self._from_providers(url, by_url.get(url, [])))
        return indicators

    # ------------------------------------------------------------ intrinsic
    def _intrinsic(self, url: str) -> list[UrlIndicator]:
        out: list[UrlIndicator] = []
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        reg = registered_domain(host) or host
        tld = tld_of(host)
        sub = subdomain_of(host)

        if parsed.scheme == "http":
            out.append(UrlIndicator(
                "insecure_transport", "low",
                "URL uses plain HTTP (no TLS).",
                url, {"scheme": parsed.scheme},
            ))
        if reg in DISPOSABLE_DOMAINS:
            out.append(UrlIndicator(
                "disposable_domain", "medium",
                f"Domain '{reg}' is on the disposable-provider list.",
                url, {"domain": reg},
            ))
        if tld and tld in RISKY_TLDS:
            out.append(UrlIndicator(
                "risky_tld", "low",
                f"Top-level domain '.{tld}' is over-represented in abuse feeds.",
                url, {"tld": tld},
            ))
        if is_idn(host):
            out.append(UrlIndicator(
                "idn_host", "medium",
                "Host uses an Internationalised Domain (IDN) — check for homograph attacks.",
                url, {"host": host},
            ))
        if sub and sub.count(".") + 1 >= _MANY_SUBDOMAINS:
            out.append(UrlIndicator(
                "deep_subdomain_chain", "low",
                "URL uses an unusually deep subdomain chain (possible obfuscation).",
                url, {"subdomain": sub},
            ))
        if reg in _SHORTENERS:
            out.append(UrlIndicator(
                "url_shortener", "low",
                f"URL shortener '{reg}' hides the destination — expand before trusting.",
                url, {"shortener": reg},
            ))
        if _OBFUSCATION_RE.search(url):
            out.append(UrlIndicator(
                "url_obfuscation", "medium",
                "Excessive percent-encoding detected — commonly used to disguise payload URLs.",
                url, {},
            ))
        # Brand look-alike
        brand, sim, homograph = looks_like_brand(reg)
        if brand:
            out.append(UrlIndicator(
                "homograph_domain" if homograph else "typosquat_domain",
                "high",
                f"Domain '{reg}' visually resembles protected brand '{brand}' (similarity={sim:.2f}).",
                url, {"brand": brand, "similarity": round(sim, 2)},
            ))
        return out

    # ------------------------------------------------------------- providers
    def _from_providers(self, url: str, results: list[ProviderOutcome]) -> list[UrlIndicator]:
        out: list[UrlIndicator] = []
        for r in results:
            if r.verdict == "malicious":
                out.append(UrlIndicator(
                    "url_malicious", "critical",
                    f"{r.provider} classifies this URL as malicious.",
                    url,
                    {"provider": r.provider, "score": r.normalized_score, "raw": r.raw},
                ))
            elif r.verdict == "suspicious":
                out.append(UrlIndicator(
                    "url_suspicious", "high",
                    f"{r.provider} reports suspicious activity on this URL.",
                    url,
                    {"provider": r.provider, "score": r.normalized_score, "raw": r.raw},
                ))
            elif r.provider == "dns_ssl":
                ssl_info = (r.raw or {}).get("ssl") or {}
                if ssl_info.get("valid") is False:
                    out.append(UrlIndicator(
                        "ssl_invalid", "medium",
                        f"TLS handshake failed for host ({ssl_info.get('error', 'unknown')}).",
                        url, {"ssl": ssl_info},
                    ))
                elif ssl_info.get("self_signed"):
                    out.append(UrlIndicator(
                        "ssl_self_signed", "medium",
                        "TLS certificate is self-signed — no chain of trust.",
                        url, {"ssl": ssl_info},
                    ))
                elif (ssl_info.get("days_left") or 30) < 0:
                    out.append(UrlIndicator(
                        "ssl_expired", "high",
                        "TLS certificate is expired.",
                        url, {"ssl": ssl_info},
                    ))
        return out


url_analysis_service = UrlAnalysisService()
