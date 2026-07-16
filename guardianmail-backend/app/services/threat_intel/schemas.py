"""Common data contracts for the threat-intel platform."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal

Verdict = Literal["safe", "suspicious", "malicious", "unknown"]
Severity = Literal["safe", "low", "medium", "high", "critical"]


@dataclass
class NormalizedProviderResult:
    """Unified shape every provider adapter returns."""
    provider: str
    status: Literal["ok", "skipped", "timeout", "error", "unknown"]
    verdict: Verdict = "unknown"
    malicious: bool = False
    suspicious: bool = False
    safe: bool = False
    confidence: float = 0.0          # 0.0 – 1.0
    threat_types: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    detection_reason: str | None = None
    reference_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    error: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatVerdict:
    """Fused output from correlation engine."""
    verdict: Verdict
    severity: Severity
    risk_score: int              # 0–100
    confidence: float            # 0.0 – 1.0
    providers_agreeing: int
    providers_total: int
    indicators: list[dict[str, Any]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    provider_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
