"""Correlation, confidence & threat-score engines."""
from __future__ import annotations

from typing import Any

from .providers import PROVIDER_WEIGHTS
from .schemas import NormalizedProviderResult, Severity, ThreatVerdict, Verdict

# Indicator severity → base score points.
SEVERITY_POINTS: dict[str, int] = {
    "low": 5, "medium": 12, "high": 22, "critical": 35,
}


def _severity_from_score(score: int) -> Severity:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "safe"


def _verdict_from_score(score: int) -> Verdict:
    if score >= 65:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"


def confidence(
    provider_results: list[NormalizedProviderResult],
    indicator_count: int,
) -> tuple[float, int, int]:
    """Return (confidence 0-1, providers_agreeing, providers_total).

    Confidence rises with:
    - Number of high-reputation providers agreeing on 'malicious'.
    - Presence of local heuristic indicators.
    """
    ran = [r for r in provider_results if r.status == "ok"]
    agree = [r for r in ran if r.malicious or r.suspicious]
    if not ran and indicator_count == 0:
        return 0.0, 0, 0
    weight_sum = sum(PROVIDER_WEIGHTS.get(r.provider, 0.5) for r in agree)
    weight_max = sum(PROVIDER_WEIGHTS.get(r.provider, 0.5) for r in ran) or 1.0
    base = weight_sum / weight_max if weight_max else 0.0
    # Heuristic boost — diminishing returns.
    heur_boost = min(0.25, 0.05 * indicator_count)
    return round(min(1.0, base + heur_boost), 3), len(agree), len(ran)


def score(
    provider_results: list[NormalizedProviderResult],
    indicators: list[dict[str, Any]],
) -> int:
    """0–100 risk score."""
    s = 0
    for r in provider_results:
        if r.status != "ok":
            continue
        w = PROVIDER_WEIGHTS.get(r.provider, 0.5)
        if r.malicious:
            s += int(45 * w)
        elif r.suspicious:
            s += int(18 * w)
    for ind in indicators:
        s += SEVERITY_POINTS.get(str(ind.get("severity", "low")), 5)
    return min(100, s)


def _recommendations(v: Verdict, has_urls: bool, has_atts: bool) -> list[str]:
    if v == "malicious":
        base = [
            "Do NOT click any links or open attachments.",
            "Report the message and delete it from your inbox.",
            "Rotate credentials if you already interacted with the message.",
        ]
        if has_urls:
            base.append("Block the sender domain at the mail gateway.")
        if has_atts:
            base.append("Submit attachments to the security team for sandboxing.")
        return base
    if v == "suspicious":
        return [
            "Treat with caution — verify the sender through a known channel.",
            "Do not enter credentials or download attachments.",
        ]
    return ["No action required. Continue normal use."]


def correlate(
    provider_results: list[NormalizedProviderResult],
    indicators: list[dict[str, Any]],
    *,
    has_urls: bool = False,
    has_attachments: bool = False,
) -> ThreatVerdict:
    risk = score(provider_results, indicators)
    verdict = _verdict_from_score(risk)
    severity = _severity_from_score(risk)
    conf, agree, total = confidence(provider_results, len(indicators))

    reasons: list[str] = []
    for r in provider_results:
        if r.status == "ok" and (r.malicious or r.suspicious):
            reasons.append(
                f"{r.provider}: {r.detection_reason or r.verdict}"
            )
    for ind in indicators:
        reasons.append(f"heuristic: {ind.get('detail')}")

    return ThreatVerdict(
        verdict=verdict,
        severity=severity,
        risk_score=risk,
        confidence=conf,
        providers_agreeing=agree,
        providers_total=total,
        indicators=indicators,
        reasons=reasons,
        recommended_actions=_recommendations(verdict, has_urls, has_attachments),
        provider_results=[r.to_dict() for r in provider_results],
    )
