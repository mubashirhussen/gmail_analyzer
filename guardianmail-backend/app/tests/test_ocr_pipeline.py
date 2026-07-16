"""Unit tests for the OCR pipeline's deterministic components."""
from __future__ import annotations

from app.services.ocr.pattern_extractor import extract_patterns
from app.services.ocr.security_indicator_service import build
from app.services.ocr.sensitive_detector import detect
from app.services.ocr.validation import (
    OCRValidationError, sanitize_filename, validate_upload,
)


def test_sanitize_filename_strips_path_and_unsafe_chars():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("weird name;$.pdf") == "weird name_.pdf"
    assert sanitize_filename("") == "attachment"


def test_validate_upload_rejects_bad_mime():
    try:
        validate_upload("a.bin", "application/octet-stream", 10)
    except OCRValidationError as e:
        assert e.code == "ocr_unsupported_mime"
    else:  # pragma: no cover
        raise AssertionError("expected validation error")


def test_validate_upload_flags_double_extension():
    vu = validate_upload("invoice.pdf.exe", "image/png", 1024)
    assert vu.double_extension is True


def test_pattern_extractor_finds_urls_and_domains():
    text = "Visit https://example.com/login or email a@b.co. Call +1 202 555 0100."
    p = extract_patterns(text)
    assert "https://example.com/login" in p.urls
    assert "example.com" in p.domains
    assert "a@b.co" in p.emails
    assert any("555" in x for x in p.phones)


def test_sensitive_detector_finds_valid_card_and_jwt():
    text = (
        "card 4539 1488 0343 6467, key eyJhbGciOiJIUzI1NiJ9.abcd.efgh, "
        "aws AKIAABCDEFGHIJKLMNOP"
    )
    s = detect(text)
    assert s.counts.get("credit_card", 0) == 1
    assert s.counts.get("jwt", 0) == 1
    assert s.counts.get("aws_access_key", 0) == 1


def test_security_indicators_detect_shortener_and_typosquat():
    from app.models.ocr_report import ExtractedPatterns
    p = ExtractedPatterns(urls=[
        "https://bit.ly/abc",
        "https://paypa1-login.com/verify",
    ])
    ind = build("Please act now and verify your account", p, [])
    assert ind.shortened_urls
    assert ind.typosquat_candidates
    assert ind.urgent_language and ind.credential_prompts
