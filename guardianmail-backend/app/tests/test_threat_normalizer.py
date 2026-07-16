"""Normalizer + typosquat unit tests."""
from __future__ import annotations

from app.services.threat.normalizer import (
    extract_urls,
    is_idn,
    normalize_email,
    normalize_ip,
    normalize_url,
    registered_domain,
)
from app.services.threat.typosquat import (
    damerau_levenshtein,
    looks_like_brand,
    similarity_ratio,
)


def test_url_normalization_lowercases_host_and_drops_tracking():
    assert normalize_url("HTTP://Example.COM/path?utm_source=foo&x=1") \
        == "http://example.com/path?x=1"


def test_url_normalization_handles_missing_scheme():
    assert normalize_url("www.paypal.com/login").startswith("http://www.paypal.com")


def test_url_normalization_rejects_garbage():
    assert normalize_url("") is None
    assert normalize_url("not a url") is None or normalize_url("not a url").startswith("http://")


def test_extract_urls_deduplicates_and_normalizes():
    text = "See https://Example.com/a and http://example.com/a?utm_source=x"
    urls = extract_urls(text)
    assert len(urls) == 1


def test_registered_domain_from_deep_subdomain():
    assert registered_domain("login.paypal.com.attacker.ru") == "attacker.ru"


def test_idn_detection():
    assert is_idn("xn--pypal-4ve.com") is True
    assert is_idn("paypal.com") is False


def test_normalize_email_and_ip():
    assert normalize_email("  A.B@Example.COM. ") == "A.B@example.com"
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_ip("not-an-ip") is None


def test_damerau_levenshtein_transposition():
    assert damerau_levenshtein("paypal", "papyal") == 1


def test_similarity_ratio_bounds():
    assert similarity_ratio("paypal", "paypal") == 1.0
    assert 0.0 <= similarity_ratio("paypal", "attacker") < 0.5


def test_looks_like_brand_typosquat():
    matched, sim, homograph = looks_like_brand("paypa1.com")
    assert matched == "paypal.com"
    assert sim >= 0.75


def test_looks_like_brand_clean():
    matched, _sim, _h = looks_like_brand("random-blog.dev")
    assert matched is None
