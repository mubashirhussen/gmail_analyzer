"""Security, trust, and threat score formulae.

Design
------
Scores are all normalised to 0-100 so the frontend renders them
identically. Each score has an interpretable formula documented inline so
security reviewers can audit weightings.

Weightings are conservative defaults; tuning is done via `SCORE_WEIGHTS`
constants, not scattered magic numbers.

    security_score  ↑ = better hygiene / fewer successful attacks
    trust_score     ↑ = more trusted correspondents / fewer risky senders
    threat_score    ↑ = more incoming threats (worse — it's the pressure)
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from app.core.clock import now_utc
from app.schemas.analytics_platform import ScoreCard

Band = Literal["critical", "poor", "fair", "good", "excellent"]

# Weightings — sum need not equal 1; each term is clamped independently.
SCORE_WEIGHTS = {
    "safe_ratio": 55,          # a mostly-safe inbox is the primary signal
    "prevention_rate": 25,     # % of detected threats that were blocked
    "recency_penalty": 20,     # recent critical hits erode the score fast
}


def _band(score: int) -> Band:
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "good"
    if score >= 50:
        return "fair"
    if score >= 30:
        return "poor"
    return "critical"


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> int:
    return int(max(lo, min(hi, v)))


class SecurityScoreService:
    """Pure computation — takes already-aggregated inputs, returns cards."""

    def security_score(
        self,
        *,
        total_scanned: int,
        threats_detected: int,
        blocked: int,
        recent_critical: int,
        computed_at: datetime | None = None,
    ) -> ScoreCard:
        total = max(total_scanned, 1)
        safe_ratio = 1.0 - (threats_detected / total)
        prevention = (blocked / threats_detected) if threats_detected else 1.0
        recency_penalty = min(1.0, recent_critical / 5.0)

        raw = (
            SCORE_WEIGHTS["safe_ratio"] * safe_ratio
            + SCORE_WEIGHTS["prevention_rate"] * prevention
            + SCORE_WEIGHTS["recency_penalty"] * (1.0 - recency_penalty)
        )
        score = _clamp(raw)
        return ScoreCard(
            key="security_score", label="Security score", score=score,
            band=_band(score), computed_at=computed_at or now_utc(),
        )

    def trust_score(
        self,
        *,
        total_senders: int,
        trusted_senders: int,
        risky_senders: int,
        auth_pass_ratio: float,
        computed_at: datetime | None = None,
    ) -> ScoreCard:
        total = max(total_senders, 1)
        trusted_ratio = trusted_senders / total
        risky_ratio = risky_senders / total
        raw = (60 * trusted_ratio + 30 * auth_pass_ratio) - (35 * risky_ratio) + 30
        score = _clamp(raw)
        return ScoreCard(
            key="trust_score", label="Trust score", score=score,
            band=_band(score), computed_at=computed_at or now_utc(),
        )

    def threat_score(
        self,
        *,
        total_scanned: int,
        threats_detected: int,
        critical_count: int,
        computed_at: datetime | None = None,
    ) -> ScoreCard:
        total = max(total_scanned, 1)
        pressure = (threats_detected / total) * 100
        crit_boost = min(30, critical_count * 3)
        raw = min(100, pressure + crit_boost)
        score = _clamp(raw)
        # For threat score, "excellent" means "high pressure detected" — invert band label.
        band = _band(100 - score)
        return ScoreCard(
            key="threat_score", label="Threat pressure", score=score,
            band=band, computed_at=computed_at or now_utc(),
        )

    def protection_pct(self, *, threats: int, blocked: int) -> float:
        if threats <= 0:
            return 100.0
        return round((blocked / threats) * 100.0, 2)

    def safe_ratio(self, *, total: int, threats: int) -> float:
        if total <= 0:
            return 1.0
        return round(max(0.0, 1.0 - (threats / total)), 4)
