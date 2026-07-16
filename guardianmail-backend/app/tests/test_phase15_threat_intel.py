"""Phase 15 — Threat Intelligence Platform unit tests.

Additive. Exercises heuristics, correlation, confidence, and orchestrator
plumbing without hitting real providers.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from app.services.threat_intel import correlation, heuristics
from app.services.threat_intel.orchestrator import analyze_artifact, analyze_url
from app.services.threat_intel.providers import (DEFAULT_PROVIDERS,
                                                   registered_providers)
from app.services.threat_intel.schemas import NormalizedProviderResult


# ---- provider registry -------------------------------------------------
def test_default_providers_registered():
    names = registered_providers()
    for n in ("google_safe_browsing", "virustotal", "urlscan",
              "urlhaus", "abuseipdb", "otx", "rdap"):
        assert n in names


# ---- heuristics --------------------------------------------------------
def test_heuristic_flags_shortener():
    ind = heuristics.analyze_url("http://bit.ly/abc")
    kinds = {i["detail"] for i in ind}
    assert any("shortener" in d for d in kinds)
    assert any("non-https" in d for d in kinds)


def test_heuristic_flags_ip_url():
    ind = heuristics.analyze_url("http://192.168.1.1/login")
    assert any("IP address" in i["detail"] for i in ind)


def test_heuristic_typosquat_paypal():
    ind = heuristics.analyze_url("https://paypa1.com/login")
    assert any(i["category"] == "domain" for i in ind)


def test_heuristic_flags_executable_attachment():
    ind = heuristics.analyze_attachment({"name": "invoice.exe", "mime": ""})
    assert any(i["severity"] == "critical" for i in ind)


def test_heuristic_flags_double_extension():
    ind = heuristics.analyze_attachment({"name": "invoice.pdf.exe", "mime": ""})
    sev = [i["severity"] for i in ind]
    assert "critical" in sev or "high" in sev


def test_heuristic_urgency_and_credentials():
    ind = heuristics.analyze_text(
        "URGENT: verify your account now or your password will expire."
    )
    cats = {i["category"] for i in ind}
    assert "language" in cats
    assert len(ind) >= 2


def test_heuristic_email_auth_fail():
    ind = heuristics.analyze_email_auth({"spf": "fail", "dkim": "pass",
                                          "dmarc": "fail"})
    assert len(ind) == 2


# ---- correlation & confidence -----------------------------------------
def _r(name, verdict="malicious", malicious=True, suspicious=False):
    return NormalizedProviderResult(
        provider=name, status="ok", verdict=verdict,
        malicious=malicious, suspicious=suspicious, safe=False,
        confidence=0.9,
    )


def test_confidence_rises_with_agreement():
    one = correlation.confidence([_r("virustotal")], 0)
    two = correlation.confidence([_r("virustotal"),
                                    _r("google_safe_browsing")], 0)
    assert two[0] >= one[0]
    assert two[1] == 2


def test_score_and_verdict_malicious():
    v = correlation.correlate(
        [_r("virustotal"), _r("google_safe_browsing")],
        [{"category": "url", "severity": "high", "detail": "shortener"}],
        has_urls=True,
    )
    assert v.verdict == "malicious"
    assert v.severity in ("high", "critical")
    assert 0 < v.risk_score <= 100
    assert v.providers_agreeing == 2
    assert v.recommended_actions
    assert any("do not" in a.lower() or "block" in a.lower()
               or "rotate" in a.lower() for a in v.recommended_actions)


def test_verdict_safe_when_no_signals():
    v = correlation.correlate([], [])
    assert v.verdict == "safe"
    assert v.severity == "safe"
    assert v.risk_score == 0


# ---- orchestrator ------------------------------------------------------
async def test_analyze_url_uses_all_providers(monkeypatch):
    called: list[str] = []

    async def fake_provider_factory(name):
        async def _fn(client, url):
            called.append(name)
            return NormalizedProviderResult(
                provider=name, status="ok",
                verdict="safe", safe=True, confidence=0.5,
            )
        return _fn

    fake_providers = {
        n: await fake_provider_factory(n)
        for n in ("virustotal", "google_safe_browsing", "urlhaus")
    }

    # Bypass redis cache path.
    async def _no_redis():
        raise RuntimeError("no redis")
    with patch("app.services.threat_intel.orchestrator.get_redis",
                side_effect=_no_redis):
        v = await analyze_url("https://example.com", providers=fake_providers)

    assert set(called) == set(fake_providers.keys())
    assert v.providers_total == 3
    assert v.verdict == "safe"


async def test_analyze_artifact_merges_urls_text_attachments():
    async def clean_provider(client, url):
        return NormalizedProviderResult(
            provider="virustotal", status="ok",
            verdict="safe", safe=True, confidence=0.5,
        )
    fake = {"virustotal": clean_provider}

    async def _no_redis():
        raise RuntimeError("no redis")
    with patch("app.services.threat_intel.orchestrator.get_redis",
                side_effect=_no_redis):
        v = await analyze_artifact(
            urls=["http://bit.ly/xyz"],
            text="URGENT verify your account password now",
            attachments=[{"name": "payload.exe", "mime": ""}],
            email_auth={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
            providers=fake,
        )

    # Heuristics alone should push this into at least suspicious.
    assert v.verdict in ("suspicious", "malicious")
    assert v.risk_score > 30
    assert v.indicators
    assert v.providers_total == 1


async def test_provider_timeout_recorded():
    async def slow(client, url):
        await asyncio.sleep(10)
        return NormalizedProviderResult(provider="urlscan", status="ok")

    async def _no_redis():
        raise RuntimeError("no redis")

    # Force a very small timeout by patching the constant.
    with patch("app.services.threat_intel.orchestrator.TIMEOUT", 0.05), \
         patch("app.services.threat_intel.orchestrator.get_redis",
                side_effect=_no_redis):
        v = await analyze_url("https://example.com",
                              providers={"urlscan": slow})

    assert v.providers_total == 0  # timeout not counted as ok
    statuses = {r["status"] for r in v.provider_results}
    assert "timeout" in statuses
