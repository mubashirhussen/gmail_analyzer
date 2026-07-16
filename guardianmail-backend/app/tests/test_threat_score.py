"""Regression tests for the deterministic scoring engine."""
from __future__ import annotations

from dataclasses import dataclass

from app.services.threat.score_service import ThreatScoreService


@dataclass(slots=True)
class Ind:
    category: str
    severity: str = "info"
    detail: str = ""
    evidence: dict | None = None


def test_no_indicators_is_safe():
    r = ThreatScoreService().compute([], providers_ok=4, providers_total=4)
    assert r.verdict == "safe"
    assert r.threat_category == "safe"
    assert r.recommended_action == "allow"
    assert r.scores.threat_score == 0.0
    assert r.scores.trust_score == 100.0


def test_malicious_url_pushes_to_critical():
    inds = [Ind("url_malicious", "critical"), Ind("domain_very_new", "high")]
    r = ThreatScoreService().compute(inds, providers_ok=4, providers_total=4)
    assert r.verdict in ("high_risk", "critical")
    assert r.threat_category == "phishing"
    assert r.recommended_action in ("quarantine", "block")
    assert r.scores.trust_score < 60


def test_repeated_category_grows_sublinearly():
    single = ThreatScoreService().compute([Ind("url_suspicious")], providers_ok=4, providers_total=4)
    triple = ThreatScoreService().compute(
        [Ind("url_suspicious"), Ind("url_suspicious"), Ind("url_suspicious")],
        providers_ok=4, providers_total=4,
    )
    # more indicators → higher score, but not linearly.
    assert triple.scores.threat_score > single.scores.threat_score
    assert triple.scores.threat_score < single.scores.threat_score * 3


def test_auth_failures_reduce_security_score():
    inds = [Ind("spf_fail"), Ind("dkim_fail"), Ind("dmarc_fail")]
    r = ThreatScoreService().compute(inds, providers_ok=1, providers_total=4)
    assert r.scores.security_score < 100
    assert r.threat_category in ("impersonation", "phishing")


def test_bec_signature_detected():
    inds = [Ind("display_name_mismatch"), Ind("reply_to_mismatch")]
    r = ThreatScoreService().compute(inds, providers_ok=2, providers_total=4)
    assert r.threat_category == "business_email_compromise"


def test_confidence_scales_with_provider_coverage():
    inds = [Ind("url_suspicious")]
    low = ThreatScoreService().compute(inds, providers_ok=1, providers_total=8)
    high = ThreatScoreService().compute(inds, providers_ok=8, providers_total=8)
    assert high.scores.confidence >= low.scores.confidence
