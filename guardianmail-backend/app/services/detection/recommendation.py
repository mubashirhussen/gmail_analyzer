"""RecommendationService — turns a correlated verdict into user actions.

Deterministic mapping from classification + fraud findings to a primary
recommendation plus a list of admissible actions.
"""
from __future__ import annotations

from typing import Any


class RecommendationService:
    def recommend(
        self, *, classification: str, risk_score: float,
        fraud_findings: list[dict[str, Any]],
    ) -> tuple[str, list[str]]:
        has_bec = any(f.get("kind") == "bec_ceo_fraud" for f in fraud_findings)
        critical = classification == "critical" or risk_score >= 85 or has_bec

        if critical:
            return "escalate", [
                "delete", "block_sender", "report_phishing",
                "escalate_to_admin", "generate_evidence",
            ]
        if classification == "high" or risk_score >= 65:
            return "report_phishing", [
                "delete", "block_sender", "report_phishing", "generate_evidence",
            ]
        if classification == "medium" or risk_score >= 40:
            return "review", ["archive", "report_phishing", "ignore"]
        if classification == "low" or risk_score >= 15:
            return "open_safely", ["archive", "ignore"]
        return "open_safely", ["open", "archive"]


recommendation_service = RecommendationService()
