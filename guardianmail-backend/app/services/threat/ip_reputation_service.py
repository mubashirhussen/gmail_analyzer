"""IP reputation analysis (sender / originating IPs).

The IP is discovered by `HeaderAnalysisService.extract_origin_ip` and
handed here. Provider outcomes for AbuseIPDB drive the verdict; DNS/SSL
data augments with hosting/ASN when present.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.services.threat.normalizer import is_private_ip
from app.services.threat.providers.base import ProviderOutcome


@dataclass(slots=True)
class IpIndicator:
    category: str
    severity: str
    detail: str
    ip: str
    evidence: dict


class IpReputationService:
    def analyze(self, ip: str | None, provider_outcomes: list[ProviderOutcome]) -> list[IpIndicator]:
        out: list[IpIndicator] = []
        if not ip:
            return out
        if is_private_ip(ip):
            out.append(IpIndicator(
                "private_origin_ip", "low",
                f"Origin IP {ip} is in a private range — routing anomaly.",
                ip, {"ip": ip},
            ))
            return out
        for r in provider_outcomes:
            if r.artifact_kind != "ip" or r.artifact_value != ip:
                continue
            raw = r.raw or {}
            if r.verdict == "malicious":
                out.append(IpIndicator(
                    "ip_blacklisted", "high",
                    f"IP {ip} has a high abuse score ({raw.get('totalReports', '?')} reports).",
                    ip, raw,
                ))
            elif r.verdict == "suspicious":
                out.append(IpIndicator(
                    "ip_suspicious", "medium",
                    f"IP {ip} has been reported for abuse recently.",
                    ip, raw,
                ))
            if raw.get("isTor"):
                out.append(IpIndicator(
                    "ip_tor_exit", "medium",
                    f"IP {ip} is a Tor exit node.",
                    ip, {"isTor": True},
                ))
            usage = (raw.get("usageType") or "").lower()
            if "hosting" in usage or "data center" in usage:
                out.append(IpIndicator(
                    "ip_hosting_provider", "low",
                    f"IP {ip} belongs to a hosting provider ({raw.get('isp')}).",
                    ip, {"isp": raw.get("isp"), "usage": usage},
                ))
        return out


ip_reputation_service = IpReputationService()
