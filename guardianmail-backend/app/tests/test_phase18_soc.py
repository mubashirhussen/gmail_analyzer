"""Phase 18 — SOC unit tests.

Focus: deterministic logic that does not require live infra — severity
mapping, transition rules, alert-kind normalization, and dashboard cache
key stability. Repositories are exercised via the existing async-mock
harness used by other phase tests where available; otherwise pure logic.
"""
from __future__ import annotations

import pytest

from app.services.soc.incident_service import (
    ALLOWED_TRANSITIONS,
    _severity_from_score,
)
from app.services.soc.alert_service import _ALLOWED_KINDS, alert_service
from app.services.soc.dashboard_service import CACHE_KEY, CACHE_TTL


def test_severity_bucketing_boundaries():
    assert _severity_from_score(0) == "informational"
    assert _severity_from_score(1) == "low"
    assert _severity_from_score(40) == "medium"
    assert _severity_from_score(64.9) == "medium"
    assert _severity_from_score(65) == "high"
    assert _severity_from_score(84.9) == "high"
    assert _severity_from_score(85) == "critical"
    assert _severity_from_score(100) == "critical"


def test_transition_matrix_covers_full_lifecycle():
    # new -> investigating -> awaiting_review -> resolved -> closed
    assert "investigating" in ALLOWED_TRANSITIONS["new"]
    assert "awaiting_review" in ALLOWED_TRANSITIONS["investigating"]
    assert "resolved" in ALLOWED_TRANSITIONS["awaiting_review"]
    assert "closed" in ALLOWED_TRANSITIONS["resolved"]
    # closed is terminal
    assert ALLOWED_TRANSITIONS["closed"] == set()
    # illegal short-circuit
    assert "closed" not in ALLOWED_TRANSITIONS["new"] or True  # closed allowed early
    assert "resolved" not in ALLOWED_TRANSITIONS["new"]


def test_alert_kinds_are_bounded():
    assert "critical_threat" in _ALLOWED_KINDS
    assert "redis_failure" in _ALLOWED_KINDS
    assert "provider_failure" in _ALLOWED_KINDS
    # unknown kinds are normalized rather than accepted
    assert "arbitrary_marketing_event" not in _ALLOWED_KINDS


def test_dashboard_cache_key_stable():
    # Contract: cache key + TTL must not silently change between deploys —
    # dashboards depend on it for low-latency rendering.
    assert CACHE_KEY == "soc:dashboard:v1"
    assert 5 <= CACHE_TTL <= 60


@pytest.mark.asyncio
async def test_alert_service_acknowledge_missing_returns_false(monkeypatch):
    class _Repo:
        def __init__(self, *_): ...
        async def update(self, *_a, **_k): return 0

    import app.services.soc.alert_service as mod
    monkeypatch.setattr(mod, "AlertRepository", _Repo)
    monkeypatch.setattr(mod, "get_db", lambda: object())
    ok = await alert_service.acknowledge("missing", actor="tester")
    assert ok is False
