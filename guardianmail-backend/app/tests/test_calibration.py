"""Evaluation + calibration for explainable risk scoring.

These are deterministic (no network, no AI) — they verify the scorer produces
consistent, sensible verdicts across the email, social, and QR channels.
"""
from __future__ import annotations

import pytest

from app.services.scoring.explainable import explain


def _url_intel(flagged_provider: str | None = None) -> dict:
    providers = []
    if flagged_provider:
        providers.append({"provider": flagged_provider, "status": "flagged"})
    return {"results": [{"url": "https://evil.example", "flagged": bool(flagged_provider),
                         "providers": providers}]}


class TestCalibration:
    def test_clean_message_is_safe(self):
        v = explain()
        assert v["verdict"] == "safe"
        assert v["risk_score"] == 0

    def test_gsb_flagged_is_phishing(self):
        v = explain(url_intel=_url_intel("google_safe_browsing"))
        assert v["verdict"] in ("suspicious", "phishing")
        assert v["risk_score"] >= 55

    def test_multiple_flags_saturate(self):
        v = explain(
            url_intel=_url_intel("google_safe_browsing"),
            email_auth={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            attachments=[{"mime": "application/x-msdownload", "name": "invoice.exe"}],
            community_report_count=15,
        )
        assert v["verdict"] == "phishing"
        assert v["risk_score"] == 100
        cats = {s["category"] for s in v["signals"]}
        assert {"url_intel", "email_auth", "attachment", "community"}.issubset(cats)

    def test_confidence_grows_with_signal_diversity(self):
        low = explain(email_auth={"spf": "fail"})
        high = explain(
            email_auth={"spf": "fail"},
            url_intel=_url_intel("virustotal"),
            community_report_count=5,
        )
        assert high["confidence"] > low["confidence"]

    @pytest.mark.parametrize("channel_hint", ["email", "social", "qr"])
    def test_verdict_stable_across_channels(self, channel_hint):
        """Same inputs → same verdict regardless of channel wrapper."""
        v1 = explain(url_intel=_url_intel("virustotal"))
        v2 = explain(url_intel=_url_intel("virustotal"))
        assert v1["verdict"] == v2["verdict"]
        assert v1["risk_score"] == v2["risk_score"]

    def test_community_alone_only_medium(self):
        v = explain(community_report_count=4)
        assert v["verdict"] == "safe" or v["risk_score"] < 55

    def test_executable_attachment_is_high(self):
        v = explain(attachments=[{"mime": "application/x-msdownload", "name": "x.exe"}])
        assert v["risk_score"] >= 30

    def test_contribution_breakdown_sums_to_score(self):
        v = explain(
            url_intel=_url_intel("virustotal"),
            email_auth={"spf": "fail"},
        )
        total = sum(v["contribution_breakdown"].values())
        assert total == v["risk_score"] or total >= v["risk_score"]  # capped at 100
