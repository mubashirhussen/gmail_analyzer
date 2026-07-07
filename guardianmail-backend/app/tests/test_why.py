"""Unit tests for the "why we told you this" explainer."""
from app.services.scoring.explainable import explain
from app.services.scoring.why import build


def test_why_shape_for_phishing():
    v = explain(
        url_intel={"results": [{"url": "https://x", "providers": [
            {"provider": "google_safe_browsing", "status": "flagged"}]}]},
        email_auth={"spf": "fail"},
    )
    why = build(v, artifact_kind="email")
    assert why["artifact_kind"] == "email"
    assert why["risk_score"] == v["risk_score"]
    assert why["reasons"], "expected at least one reason block"
    assert all("device_impact" in r for r in why["reasons"])
    assert why["next_steps"]


def test_why_safe_when_no_signals():
    why = build(explain(), artifact_kind="qr")
    assert why["verdict"] == "safe"
    assert why["reasons"] == []
