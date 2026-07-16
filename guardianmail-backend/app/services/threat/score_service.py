"""Threat scoring engine.

Deterministic, explainable score computation. Given the flat list of
indicators produced by the analysis services, this module returns a
`ScoreBundle`, verdict, category, and recommended action — with the
mapping table in `config.py` as the only source of truth.

The scorer never touches I/O so it is trivially unit-testable and
deterministic for a given indicator set.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from app.models.threat import ScoreBundle
from app.services.threat.config import (
    RECOMMENDED_ACTION,
    ScoreWeights,
    band,
)


@dataclass(slots=True)
class ScoringResult:
    scores: ScoreBundle
    verdict: str
    threat_category: str
    severity: str
    recommended_action: str
    reasons: list[str]


# category → weight-field mapping. Missing categories contribute 0.
_CATEGORY_WEIGHT = {
    "url_malicious":              "url_malicious_provider",
    "url_suspicious":             "url_suspicious_provider",
    "domain_new":                 "domain_new",
    "domain_very_new":            "domain_very_new",
    "risky_tld":                  "domain_risky_tld",
    "disposable_domain":          "domain_disposable",
    "typosquat_domain":           "domain_typosquat",
    "homograph_domain":           "domain_homograph",
    "ssl_expired":                "ssl_expired",
    "ssl_self_signed":            "ssl_self_signed",
    "spf_fail":                   "spf_fail",
    "dkim_fail":                  "dkim_fail",
    "dmarc_fail":                 "dmarc_fail",
    "dmarc_missing":              "dmarc_missing",
    "reply_to_mismatch":          "reply_to_mismatch",
    "return_path_mismatch":       "return_path_mismatch",
    "display_name_mismatch":      "display_name_mismatch",
    "forged_received":            "forged_received",
    "timestamp_skew":              "timestamp_anomaly",
    "future_timestamp":            "timestamp_anomaly",
    "executable_attachment":      "attachment_executable",
    "double_extension":           "attachment_double_ext",
    "macro_office_document":      "attachment_macro_office",
    "encrypted_archive":          "attachment_encrypted_archive",
    "known_malware_hash":         "attachment_known_malware_hash",
    "ip_blacklisted":             "ip_blacklisted",
    "ip_tor_exit":                "ip_tor",
    "ip_hosting_provider":        "ip_hosting",
}


def _category_to_threat(indicator_categories: Counter[str]) -> str:
    if any(c in indicator_categories for c in (
        "known_malware_hash", "executable_attachment", "macro_office_document",
        "double_extension",
    )):
        return "malware"
    if any(c in indicator_categories for c in (
        "url_malicious", "domain_malicious", "url_suspicious",
        "typosquat_domain", "homograph_domain", "display_name_mismatch",
        "reply_to_mismatch",
    )):
        return "phishing"
    if "display_name_mismatch" in indicator_categories \
            and "reply_to_mismatch" in indicator_categories:
        return "business_email_compromise"
    if any(c in indicator_categories for c in (
        "spf_fail", "dkim_fail", "dmarc_fail",
    )):
        return "impersonation"
    return "safe"


class ThreatScoreService:
    def __init__(self, weights: ScoreWeights | None = None) -> None:
        self.weights = weights or ScoreWeights()

    def compute(
        self,
        indicators: Iterable,
        *,
        providers_ok: int,
        providers_total: int,
    ) -> ScoringResult:
        threat_score = 0.0
        counts: Counter[str] = Counter()
        reasons: list[str] = []
        for ind in indicators:
            cat = getattr(ind, "category", None)
            if not cat:
                continue
            counts[cat] += 1
            weight_field = _CATEGORY_WEIGHT.get(cat)
            if not weight_field:
                continue
            weight = float(getattr(self.weights, weight_field))
            # First occurrence of a category weights fully; repeats
            # add 25% each up to 3x — so many bad URLs is worse than
            # one bad URL but not linearly.
            multiplier = min(counts[cat], 3) - 1
            contribution = weight * (1.0 + 0.25 * multiplier)
            threat_score += contribution
            reasons.append(f"{cat} (+{contribution:.1f})")

        threat_score = max(0.0, min(100.0, threat_score))
        verdict = band(threat_score)
        threat_category = _category_to_threat(counts)
        if verdict == "safe":
            threat_category = "safe"
        severity_map = {
            "safe": "info",
            "low_risk": "low",
            "medium_risk": "medium",
            "high_risk": "high",
            "critical": "critical",
        }
        severity = severity_map[verdict]

        coverage = (providers_ok / providers_total) if providers_total else 0.0
        confidence = max(0.1, min(1.0, 0.4 * coverage + 0.6 * (min(len(reasons), 6) / 6)))

        security_score = max(0.0, 100.0 - min(
            100.0,
            (
                self.weights.spf_fail * bool(counts["spf_fail"])
                + self.weights.dkim_fail * bool(counts["dkim_fail"])
                + self.weights.dmarc_fail * bool(counts["dmarc_fail"])
                + self.weights.dmarc_missing * bool(counts["dmarc_missing"])
                + self.weights.ssl_expired * bool(counts["ssl_expired"])
                + self.weights.ssl_self_signed * bool(counts["ssl_self_signed"])
            ),
        ))
        trust_score = max(0.0, 100.0 - threat_score)

        return ScoringResult(
            scores=ScoreBundle(
                threat_score=round(threat_score, 2),
                trust_score=round(trust_score, 2),
                security_score=round(security_score, 2),
                confidence=round(confidence, 2),
            ),
            verdict=verdict,
            threat_category=threat_category,
            severity=severity,
            recommended_action=RECOMMENDED_ACTION[verdict],
            reasons=reasons,
        )


threat_score_service = ThreatScoreService()
