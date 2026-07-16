"""AI output validator + hallucination guard.

Every LLM response passes through this service before persistence:

1. Structural — required fields present, enums in range.
2. Grounding — every `evidence_used[*].category` must appear in the
   source ThreatReport's indicators/evidence. Cited categories that do
   not exist upstream raise the hallucination score.
3. Consistency — `risk_level` must be aligned with the ThreatReport's
   score band (e.g. score >= 80 must not produce `risk_level=none`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models.threat import ThreatReport

_VERDICTS = {
    "safe", "suspicious", "spam", "phishing", "credential_theft",
    "business_email_compromise", "malware", "invoice_fraud",
    "payment_scam", "identity_theft", "fake_login", "qr_phishing",
    "unknown",
}
_RISK_LEVELS = {"none", "low", "medium", "high", "critical"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_REQUIRED = (
    "verdict", "risk_level", "threat_summary", "executive_summary",
    "detailed_explanation", "reasoning", "evidence_used",
    "immediate_actions", "long_term_recommendations", "educational_tips",
)


@dataclass(slots=True)
class ValidationResult:
    passed: bool
    errors: list[str] = field(default_factory=list)
    hallucination_score: float = 0.0
    cleaned: dict = field(default_factory=dict)


class AIValidationService:
    def validate(self, parsed: dict, threat_report: ThreatReport) -> ValidationResult:
        errors: list[str] = []
        cleaned: dict = dict(parsed or {})

        # ----- structural checks -----------------------------------
        for key in _REQUIRED:
            if key not in cleaned:
                errors.append(f"missing:{key}")

        verdict = str(cleaned.get("verdict", "unknown")).lower().strip()
        if verdict not in _VERDICTS:
            errors.append(f"invalid_verdict:{verdict}")
            verdict = "unknown"
        cleaned["verdict"] = verdict

        risk_level = str(cleaned.get("risk_level", "none")).lower().strip()
        if risk_level not in _RISK_LEVELS:
            errors.append(f"invalid_risk_level:{risk_level}")
            risk_level = "none"
        cleaned["risk_level"] = risk_level

        # ----- normalize lists -------------------------------------
        for key in ("reasoning", "immediate_actions", "long_term_recommendations",
                    "educational_tips", "technical_notes", "possible_consequences"):
            v = cleaned.get(key) or []
            cleaned[key] = [str(x).strip() for x in v if str(x).strip()]

        evidence_used = cleaned.get("evidence_used") or []
        norm_evidence: list[dict] = []
        allowed_categories = {
            (e.get("category") or "").strip() for e in threat_report.evidence
        }
        allowed_categories.update(
            (i.get("category") or "") for i in threat_report.indicators.top
        )
        hallucinated = 0
        for e in evidence_used:
            if not isinstance(e, dict):
                continue
            cat = str(e.get("category", "")).strip()
            sev = str(e.get("severity", "info")).lower()
            if sev not in _SEVERITIES:
                sev = "info"
            weight = float(e.get("weight", 0.5) or 0.0)
            weight = max(0.0, min(1.0, weight))
            if allowed_categories and cat and cat not in allowed_categories:
                hallucinated += 1
            norm_evidence.append({
                "category": cat, "detail": str(e.get("detail", ""))[:400],
                "severity": sev, "weight": weight,
            })
        cleaned["evidence_used"] = norm_evidence

        # ----- clamp numeric fields --------------------------------
        try:
            mc = float(cleaned.get("model_confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            mc = 0.0
        cleaned["model_confidence"] = max(0.0, min(100.0, mc))

        try:
            adj = float(cleaned.get("trust_score_adjustment", 0.0) or 0.0)
        except (TypeError, ValueError):
            adj = 0.0
        cleaned["trust_score_adjustment"] = max(-40.0, min(20.0, adj))

        # ----- consistency vs threat score -------------------------
        score = threat_report.risk_score
        if score >= 80 and risk_level in {"none", "low"}:
            errors.append("risk_level_underrates_score")
        if score <= 10 and risk_level in {"high", "critical"}:
            errors.append("risk_level_overrates_score")

        # ----- hallucination score ---------------------------------
        total_cites = max(1, len(norm_evidence))
        hallucination_score = round(hallucinated / total_cites, 3)

        passed = not errors and hallucination_score <= 0.35
        return ValidationResult(
            passed=passed, errors=errors,
            hallucination_score=hallucination_score, cleaned=cleaned,
        )
