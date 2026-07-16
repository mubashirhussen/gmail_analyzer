from app.utils.fingerprint import compose
from app.utils.user_agent import parse


def test_ua_parse():
    ua = parse("Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/120.0 Safari/537")
    assert ua.browser == "Chrome"
    assert "Windows" in ua.os
    assert ua.device_type == "desktop"


def test_ua_mobile():
    ua = parse("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile Safari")
    assert ua.device_type == "mobile"


def test_fingerprint_stable():
    a = compose("abc", "1.2.3.4", "Chrome")
    b = compose("abc", "1.2.9.9", "Chrome")   # same /16
    c = compose("abc", "9.9.9.9", "Chrome")   # different network
    assert a == b
    assert a != c
