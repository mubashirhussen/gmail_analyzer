"""Confidence calculation for AI decisions.

The AI's self-reported confidence is one signal, but not the only one.
We combine it with objective coverage metrics (how many providers
responded, how much evidence backs the verdict, how complete the input
was) to produce a defensible overall confidence.
"""
from __future__ import annotations

from app.models.ai_report import ConfidenceBreakdown
from app.models.threat import ThreatReport
from app.services.ai.config import config


class ConfidenceService:
    def compute(
        self,
        *,
        threat_report: ThreatReport,
        model_confidence: float,
        evidence_used_count: int,
        reasoning_count: int,
        validation_passed: bool,
    ) -> ConfidenceBreakdown:
        # --- evidence strength: 1 evidence ~ +10, capped at 100 ------
        evidence_strength = min(100.0, evidence_used_count * 12.0)
        # --- provider agreement: ok / total ratio scaled ------------
        total = max(1, threat_report.providers_total)
        provider_agreement = (threat_report.providers_ok / total) * 100.0
        # --- data completeness --------------------------------------
        completeness_bits = [
            bool(threat_report.evidence),
            threat_report.urls_analyzed > 0,
            threat_report.domains_analyzed > 0,
            threat_report.attachments_analyzed >= 0,
            threat_report.providers_ok > 0,
        ]
        data_completeness = (sum(completeness_bits) / len(completeness_bits)) * 100.0
        # --- reliability --------------------------------------------
        reliability = 100.0 if validation_passed else 55.0
        if reasoning_count < 2:
            reliability *= 0.6

        overall = (
            config.w_evidence * evidence_strength
            + config.w_providers * provider_agreement
            + config.w_model * max(0.0, min(100.0, model_confidence))
            + config.w_completeness * data_completeness
            + config.w_reliability * reliability
        )
        return ConfidenceBreakdown(
            overall=round(overall, 2),
            evidence_strength=round(evidence_strength, 2),
            provider_agreement=round(provider_agreement, 2),
            model_confidence=round(max(0.0, min(100.0, model_confidence)), 2),
            data_completeness=round(data_completeness, 2),
            reliability=round(reliability, 2),
        )
