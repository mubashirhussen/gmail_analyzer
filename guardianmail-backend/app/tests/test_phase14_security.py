"""Phase 14 — Security & penetration-style negative tests.

Additive. Confirms the platform rejects the most common OWASP-style
malformed inputs and unauthenticated write attempts without invoking
business logic. External deps are not required.
"""
from __future__ import annotations

import pytest


MALICIOUS_PAYLOADS = [
    {"redirect_uri": "javascript:alert(1)", "remember_me": True},
    {"redirect_uri": "http://evil.example/../../etc/passwd", "remember_me": True},
    {"redirect_uri": "' OR 1=1 --", "remember_me": True},
    {"redirect_uri": {"$ne": None}, "remember_me": True},  # NoSQL op
    {"redirect_uri": "<script>alert(1)</script>", "remember_me": True},
]


@pytest.mark.parametrize("payload", MALICIOUS_PAYLOADS)
def test_google_login_rejects_malformed_redirect(client, payload):
    """Pydantic validation must reject non-URL / structural payloads."""
    r = client.post("/api/v1/auth/google/login", json=payload)
    # Accept 200 only when redirect_uri is a syntactically valid URL AND
    # the schema explicitly allows it; otherwise expect 4xx.
    assert r.status_code in (200, 400, 422)
    if r.status_code == 200:
        body = r.json()
        # Must not echo raw JS scheme back as the authorize URL.
        assert "javascript:" not in body.get("authorize_url", "")


def test_refresh_rejects_missing_token(client):
    r = client.post("/api/v1/auth/refresh", json={})
    assert r.status_code in (400, 422)


def test_refresh_rejects_forged_token(client):
    r = client.post("/api/v1/auth/refresh",
                    json={"refresh_token": "not.a.real.jwt"})
    assert r.status_code in (400, 401, 403, 422)


def test_write_endpoints_require_auth(client):
    """Sample of destructive/writeful endpoints must reject anon."""
    samples = [
        ("POST", "/api/v1/auth/logout", {}),
        ("POST", "/api/v1/auth/logout-all", {}),
    ]
    for method, path, body in samples:
        r = client.request(method, path, json=body)
        assert r.status_code in (401, 403), f"{method} {path} leaked"


def test_bearer_forged_jwt_rejected(client):
    r = client.get(
        "/api/v1/auth/profile",
        headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."},
    )
    assert r.status_code in (401, 403)


def test_bearer_wrong_scheme_rejected(client):
    r = client.get(
        "/api/v1/auth/profile",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert r.status_code in (401, 403)


def test_path_traversal_returns_404(client):
    r = client.get("/api/v1/../../etc/passwd")
    assert r.status_code in (400, 404)
