"""Tests for Gmail header parsing + URL extraction (pure functions, no I/O)."""
from __future__ import annotations

from app.services.gmail.headers_service import header_parser_service
from app.services.gmail.url_extraction_service import url_extraction_service


def test_header_parser_extracts_auth_verdicts():
    headers = [
        {"name": "From", "value": "Alice <alice@example.com>"},
        {"name": "Message-ID", "value": "<abc@example.com>"},
        {"name": "Reply-To", "value": "bob@evil.com"},
        {"name": "Authentication-Results",
         "value": "mx.google.com; spf=pass smtp.mailfrom=example.com; "
                  "dkim=pass header.d=example.com; dmarc=fail action=none"},
        {"name": "Received", "value": "from mx1.example.com by google.com"},
        {"name": "Received", "value": "from mx2.example.com by google.com"},
        {"name": "X-Originating-IP", "value": "[203.0.113.5]"},
        {"name": "List-Unsubscribe", "value": "<https://x/unsub>"},
    ]
    parsed = header_parser_service.parse(headers)
    assert parsed.message_id == "<abc@example.com>"
    assert parsed.reply_to == "bob@evil.com"
    assert parsed.spf == "pass"
    assert parsed.dkim == "pass"
    assert parsed.dmarc == "fail"
    assert parsed.x_originating_ip == "[203.0.113.5]"
    assert len(parsed.received) == 2
    assert parsed.list_unsubscribe.startswith("<https://x")


def test_url_extraction_dedupes_and_normalises():
    text = "See https://Example.com/a and http://example.com/a."
    html = ('<a href="https://phish.example.co.uk/login?u=1">click</a>'
            '<img src="https://track.example.com/img.gif">'
            'https://Example.com/a')
    refs = url_extraction_service.extract(text=text, html=html)
    normalised = {r.normalized for r in refs}
    # case-insensitive host + trailing punctuation strip + dedup
    assert "https://example.com/a" in normalised
    assert "http://example.com/a" in normalised
    assert any(r.domain == "example.co.uk" for r in refs)
    assert any(r.source == "button" for r in refs)
    assert any(r.source == "image" for r in refs)
    # subdomain parsed
    phish = next(r for r in refs if "phish" in r.normalized)
    assert phish.subdomain == "phish"
    assert phish.domain == "example.co.uk"
