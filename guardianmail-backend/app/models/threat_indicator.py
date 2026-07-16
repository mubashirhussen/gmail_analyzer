"""Threat indicator (IOC) document.

One row per artefact observed inside a threat report: URL, domain, IP,
attachment hash, or auth-result signature. Stored separately from
`threats` so we can (a) build a global reputation graph and (b) query
"has anyone else seen this IOC?" without loading full reports.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.models.base import Document

IndicatorKind = Literal["url", "domain", "ip", "file_hash", "email_addr", "header"]
IndicatorSeverity = Literal["info", "low", "medium", "high", "critical"]


class AuthResults(Document):
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


class ProviderVerdict(Document):
    provider: str  # virustotal | safe_browsing | urlscan | urlhaus | phishtank
    verdict: str  # clean | suspicious | malicious | unknown
    score: float | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ThreatIndicator(Document):
    threat_report_id: str
    user_id: str

    kind: IndicatorKind
    value: str  # canonical form (lowercased domain, sha256 hex, etc.)
    value_hash: str  # sha256(value) — used for global de-duplication

    severity: IndicatorSeverity = "info"
    confidence: float = 0.0  # 0..1

    # per-provider intel snapshots
    verdicts: list[ProviderVerdict] = Field(default_factory=list)
    whois: dict[str, Any] | None = None
    auth_results: AuthResults | None = None

    first_seen: str | None = None  # ISO date
    last_seen: str | None = None
