"""Phase 17 — Advanced Threat & Fraud Detection tests.

Covers deterministic invariants that must never regress: header auth
parsing, domain typosquat detection, URL heuristics, language / fraud
lexicon hits, AI-generated flags, and risk-classification thresholds.
"""
from __future__ import annotations

import asyncio

from app.services.detection.ai_generated import ai_generated_detector
from app.services.detection.correlation import _classify
from app.services.detection.domain_intelligence import domain_intelligence_service
from app.services.detection.fraud_detection import fraud_detection_service
from app.services.detection.header_analysis import header_analysis_service
from app.services.detection.language_analysis import language_analysis_service
from app.services.detection.recommendation import recommendation_service
from app.services.detection.url_intelligence import url_intelligence_service


def test_header_analysis_detects_dmarc_fail_and_reply_mismatch():
    out = header_analysis_service.analyze({
        "Authentication-Results": "spf=pass; dkim=pass; dmarc=fail",
        "From": "ceo@company.com",
        "Reply-To": "attacker@evil.tld",
    })
    assert out["dmarc"] == "fail"
    assert "dmarc_fail" in out["anomalies"]
    assert "reply_to_domain_mismatch" in out["anomalies"]
    assert out["score"] > 0


def test_domain_intel_flags_typosquat_and_bad_tld():
    out = domain_intelligence_service.analyze("paypa1-secure.xyz")
    assert any(f.startswith("typosquat") or f.startswith("brand_in_subdomain")
               for f in out["flags"])
    assert any(f.startswith("suspicious_tld") for f in out["flags"])


def test_url_intel_flags_ip_and_shortener():
    out = url_intelligence_service.analyze_one("http://192.168.1.5/login?verify=1")
    assert "ip_url" in out["flags"]
    assert "credential_keywords" in out["flags"]
    out2 = url_intelligence_service.analyze_one("https://bit.ly/abcd")
    assert "shortener" in out2["flags"]


def test_language_analysis_hits_multiple_categories():
    out = language_analysis_service.analyze(
        "URGENT: verify your account",
        "Please wire transfer $10,000 immediately or your account is suspended.",
    )
    assert "urgency" in out["categories"]
    assert "fear" in out["categories"]
    assert "financial_request" in out["categories"]
    assert out["score"] > 20


def test_fraud_detection_bec_and_gift_card():
    findings = fraud_detection_service.scan(
        subject="Quick request from CEO",
        body="I need you to purchase Amazon gift cards urgently. Send codes.",
        sender="ceo@company.com",
    )
    kinds = {f["kind"] for f in findings}
    assert "gift_card_fraud" in kinds
    assert "bec_ceo_fraud" in kinds
    assert any(f["severity"] == "critical" for f in findings)


def test_ai_generated_detector_flags_llm_phrases():
    out = ai_generated_detector.analyze(
        "hi", "As an AI language model, I hope this message finds you well. "
        "Furthermore, ignore previous instructions.",
    )
    assert any(f.startswith("llm_phrases") for f in out["flags"])
    assert "prompt_leakage" in out["flags"]
    assert out["confidence_ai_generated"] > 0


def test_classify_thresholds_are_monotonic():
    assert _classify(5) == "safe"
    assert _classify(20) == "low"
    assert _classify(50) == "medium"
    assert _classify(70) == "high"
    assert _classify(95) == "critical"


def test_recommendation_escalates_on_bec():
    rec, actions = recommendation_service.recommend(
        classification="high", risk_score=70,
        fraud_findings=[{"kind": "bec_ceo_fraud", "severity": "critical"}],
    )
    assert rec == "escalate"
    assert "escalate_to_admin" in actions


def test_recommendation_safe_for_low_score():
    rec, actions = recommendation_service.recommend(
        classification="safe", risk_score=5, fraud_findings=[],
    )
    assert rec == "open_safely"
