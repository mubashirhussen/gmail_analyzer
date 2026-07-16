"""Domain reputation analysis.

Consumes RDAP + provider outcomes for domains and produces indicators
covering age, registrar transparency, blacklist status, and hosting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.services.threat.providers.base import ProviderOutcome


@dataclass(slots=True)
class DomainIndicator:
    category: str
    severity: str
    detail: str
    domain: str
    evidence: dict


class DomainAnalysisService:
    def analyze(
        self,
        domains: Iterable[str],
        provider_outcomes: list[ProviderOutcome],
    ) -> list[DomainIndicator]:
        by_domain: dict[str, list[ProviderOutcome]] = {}
        for o in provider_outcomes:
            if o.artifact_kind != "domain":
                continue
            by_domain.setdefault(o.artifact_value, []).append(o)
        out: list[DomainIndicator] = []
        for d in domains:
            for r in by_domain.get(d, []):
                out.extend(self._from_provider(d, r))
        return out

    def _from_provider(self, domain: str, r: ProviderOutcome) -> list[DomainIndicator]:
        indicators: list[DomainIndicator] = []
        if r.provider == "rdap":
            raw = r.raw or {}
            age = raw.get("age_days")
            if age is not None and age < 7:
                indicators.append(DomainIndicator(
                    "domain_very_new", "high",
                    f"Domain registered {age} day(s) ago — extremely young.",
                    domain, {"age_days": age},
                ))
            elif age is not None and age < 30:
                indicators.append(DomainIndicator(
                    "domain_new", "medium",
                    f"Domain registered {age} day(s) ago — less than 30 days old.",
                    domain, {"age_days": age},
                ))
            if raw.get("whois_privacy"):
                indicators.append(DomainIndicator(
                    "whois_privacy", "low",
                    "Registrant details are hidden by WHOIS privacy.",
                    domain, {"registrar": raw.get("registrar")},
                ))
            if raw.get("exists") is False:
                indicators.append(DomainIndicator(
                    "domain_not_registered", "high",
                    "Domain is not registered — likely spoofed sender.",
                    domain, {},
                ))
        elif r.verdict == "malicious":
            indicators.append(DomainIndicator(
                "domain_malicious", "critical",
                f"{r.provider} classifies domain as malicious.",
                domain, {"provider": r.provider, "raw": r.raw},
            ))
        elif r.verdict == "suspicious":
            indicators.append(DomainIndicator(
                "domain_suspicious", "high",
                f"{r.provider} reports suspicious activity on domain.",
                domain, {"provider": r.provider, "raw": r.raw},
            ))
        return indicators


domain_analysis_service = DomainAnalysisService()
