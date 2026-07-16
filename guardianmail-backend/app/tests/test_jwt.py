from datetime import timedelta

from app.core.clock import now_utc
from app.services.auth.jwt_service import JWTService


def test_access_token_roundtrip():
    svc = JWTService()
    token, ttl = svc.issue_access(user_id="u1", session_id="s1",
                                   device_id="d1", email="a@b.co")
    payload = svc.decode(token, expected_type="access")
    assert payload["sub"] == "u1" and payload["sid"] == "s1"
    assert payload["did"] == "d1" and payload["type"] == "access"
    assert ttl > 0


def test_refresh_hash_stable():
    svc = JWTService()
    tok, h = svc.issue_refresh(user_id="u", session_id="s", device_id="d", jti="j1")
    assert svc.hash_token(tok) == h


def test_wrong_type_rejected():
    import pytest
    from app.core.exceptions import AuthError
    svc = JWTService()
    tok, _ = svc.issue_access(user_id="u", session_id="s", device_id="d", email="a@b.co")
    with pytest.raises(AuthError):
        svc.decode(tok, expected_type="refresh")
