from datetime import datetime

from app.models.threat import (
    IndicatorRollup,
    ProviderStatus,
    ScoreBundle,
    ThreatReport,
)
from app.services.ai.ai_validation_service import AIValidationService
from app.services.ai.confidence_service import ConfidenceService
from app.services.ai.prompt_builder_service import PromptBuilderService
from app.services.ai.recommendation_service import RecommendationService


def _threat_report() -> ThreatReport:
    return ThreatReport(
        user_id="u1",
        email_id="e1",
        verdict="high_risk",
        threat_category="phishing",
        severity="high",
        scores=ScoreBundle(threat_score=82, trust_score=15,
                           security_score=40, confidence=0.7),
        risk_score=82,
        scan_status="completed",
        providers=[
            ProviderStatus(provider="virustotal", status="ok", latency_ms=120),
            ProviderStatus(provider="urlscan", status="ok", latency_ms=200),
        ],
        providers_ok=2,
        providers_total=2,
        summary="Malicious URL detected",
        why=["VirusTotal flagged domain", "SPF failed"],
        evidence=[
            {"category": "url_malicious_provider",
             "detail": "vt hits=5", "evidence": {"url": "http://x.test"}},
            {"category": "spf_fail",
             "detail": "spf=fail", "evidence": {}},
        ],
        indicators=IndicatorRollup(
            total=2, by_severity={"high": 2},
            by_kind={"url": 1, "header": 1},
            top=[{"category": "url_malicious_provider", "severity": "high",
                  "detail": "vt hits=5"}],
        ),
        urls_analyzed=1,
        domains_analyzed=1,
        attachments_analyzed=0,
    )


def test_prompt_is_deterministic():
    r = _threat_report()
    p1 = PromptBuilderService().build(r)
    p2 = PromptBuilderService().build(r)
    assert p1.prompt_hash == p2.prompt_hash
    assert "verdict_hint" in p1.user


def test_validator_rejects_invalid_verdict():
    r = _threat_report()
    v = AIValidationService().validate(
        {
            "verdict": "definitely-bad",
            "risk_level": "high",
            "threat_summary": "s", "executive_summary": "s",
            "detailed_explanation": "s", "reasoning": ["a"],
            "evidence_used": [{"category": "url_malicious_provider",
                                "detail": "d", "severity": "high", "weight": 1}],
            "immediate_actions": ["do"], "long_term_recommendations": ["do"],
            "educational_tips": ["t"], "model_confidence": 70,
        },
        r,
    )
    assert not v.passed
    assert any(e.startswith("invalid_verdict") for e in v.errors)
    assert v.cleaned["verdict"] == "unknown"


def test_validator_flags_hallucinated_evidence():
    r = _threat_report()
    v = AIValidationService().validate(
        {
            "verdict": "phishing", "risk_level": "high",
            "threat_summary": "s", "executive_summary": "s",
            "detailed_explanation": "s", "reasoning": ["a"],
            "evidence_used": [
                {"category": "totally_made_up_signal", "detail": "d",
                 "severity": "high", "weight": 0.9},
            ],
            "immediate_actions": ["a"], "long_term_recommendations": ["a"],
            "educational_tips": ["t"], "model_confidence": 90,
        },
        r,
    )
    assert v.hallucination_score > 0.5


def test_validator_enforces_score_consistency():
    r = _threat_report()  # risk_score=82
    v = AIValidationService().validate(
        {
            "verdict": "safe", "risk_level": "none",
            "threat_summary": "s", "executive_summary": "s",
            "detailed_explanation": "s", "reasoning": ["a"],
            "evidence_used": [], "immediate_actions": ["a"],
            "long_term_recommendations": ["a"],
            "educational_tips": ["t"], "model_confidence": 80,
        },
        r,
    )
    assert "risk_level_underrates_score" in v.errors


def test_confidence_combines_axes():
    r = _threat_report()
    c = ConfidenceService().compute(
        threat_report=r, model_confidence=80.0,
        evidence_used_count=3, reasoning_count=4, validation_passed=True,
    )
    assert 0 <= c.overall <= 100
    assert c.provider_agreement == 100.0


def test_recommendation_service_forces_critical_actions():
    recs = RecommendationService().build(
        risk_level="critical",
        immediate=["Delete the email"],
        long_term=["Enable MFA"],
        educational=["Learn phishing signs"],
        technical=[],
    )
    actions = {r.action.lower() for r in recs}
    assert "do not click any links in this email." in actions
    assert any(r.category == "long_term" for r in recs)
