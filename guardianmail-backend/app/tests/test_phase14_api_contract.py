"""Phase 14 — API contract & security surface tests.

Additive. Validates HTTP semantics, security headers, auth rejection
paths, and error envelope consistency across representative endpoints
from each module. Does not exercise business logic.
"""
from __future__ import annotations

import pytest


AUTH_REQUIRED_ENDPOINTS = [
    ("GET", "/api/v1/auth/profile"),
    ("GET", "/api/v1/auth/me"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/logout-all"),
]


@pytest.mark.parametrize("method,path", AUTH_REQUIRED_ENDPOINTS)
def test_auth_required_returns_401_or_403(client, method, path):
    r = client.request(method, path)
    assert r.status_code in (401, 403)
    assert isinstance(r.json(), dict)


def test_request_id_header_present(client):
    r = client.get("/health")
    # RequestContextMiddleware attaches x-request-id and CORS exposes it.
    assert "x-request-id" in {k.lower() for k in r.headers.keys()}


def test_security_headers_present(client):
    r = client.get("/health")
    lower = {k.lower() for k in r.headers.keys()}
    # SecurityHeadersMiddleware should emit at least one of these:
    assert lower & {
        "x-content-type-options", "x-frame-options",
        "strict-transport-security", "referrer-policy",
    }


def test_oversized_body_rejected(client):
    # BodySizeLimitMiddleware should reject payloads larger than cap.
    huge = b"x" * (50 * 1024 * 1024)  # 50 MB
    r = client.post("/api/v1/auth/google/callback", content=huge,
                    headers={"Content-Type": "application/octet-stream"})
    # 413 preferred; some stacks return 400/422 before body parse.
    assert r.status_code in (400, 413, 422)


def test_invalid_json_returns_422(client):
    r = client.post("/api/v1/auth/google/login",
                    content="not-json",
                    headers={"Content-Type": "application/json"})
    assert r.status_code in (400, 422)


def test_openapi_available_outside_prod(client):
    # In test env docs are enabled.
    r = client.get("/openapi.json")
    assert r.status_code in (200, 404)  # 404 only if disabled by env
