"""Header + authentication parsing tests."""
from __future__ import annotations

from datetime import datetime, timezone

from app.services.threat.authentication_analysis_service import (
    authentication_analysis_service,
)
from app.services.threat.header_analysis_service import header_analysis_service


def _h(name: str, value: str) -> dict:
    return {"name": name, "value": value}


def test_authentication_results_all_pass_produces_no_indicators():
    headers = [
        _h("Authentication-Results", "mx.google.com; spf=pass smtp.mailfrom=x@example.com; "
                                     "dkim=pass header.d=example.com; dmarc=pass"),
        _h("From", "Bob <bob@example.com>"),
        _h("Reply-To", "bob@example.com"),
        _h("Return-Path", "<bob@example.com>"),
    ]
    results, inds = authentication_analysis_service.analyze(headers)
    assert results == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert inds == []


def test_spf_fail_and_reply_to_mismatch_detected():
    headers = [
        _h("Authentication-Results",
           "mx.google.com; spf=fail; dkim=none; dmarc=fail"),
        _h("From", "Chase Support <no-reply@chase.com>"),
        _h("Reply-To", "attacker@evil.tk"),
    ]
    _r, inds = authentication_analysis_service.analyze(headers)
    cats = {i.category for i in inds}
    assert "spf_fail" in cats
    assert "dmarc_fail" in cats
    assert "reply_to_mismatch" in cats


def test_display_name_impersonation_flagged():
    headers = [
        _h("Authentication-Results", "mx; spf=pass; dkim=pass; dmarc=pass"),
        _h("From", "PayPal Security <notify@random.xyz>"),
    ]
    _r, inds = authentication_analysis_service.analyze(headers)
    assert any(i.category == "display_name_mismatch" for i in inds)


def test_header_origin_ip_extraction():
    headers = [
        _h("Received", "from mx.attacker.ru ([203.0.113.9]) by mail.google.com"),
        _h("Received", "from client ([10.0.0.5]) by mx.attacker.ru"),
    ]
    ip = header_analysis_service.extract_origin_ip(headers)
    assert ip == "10.0.0.5"


def test_future_timestamp_flagged():
    headers = [_h("Date", "Wed, 01 Jan 2099 12:00:00 +0000"),
               _h("Message-ID", "<x@y>"), _h("Received", "from x by y")]
    inds = header_analysis_service.analyze(headers, sent_at=datetime.now(timezone.utc))
    assert any(i.category == "future_timestamp" for i in inds)
