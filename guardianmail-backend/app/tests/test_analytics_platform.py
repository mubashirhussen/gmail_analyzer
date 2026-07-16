"""Module 10 tests — analytics platform sanity checks.

The tests exercise the pure computation surfaces (time filters, KPI cards,
security scores, aggregation helpers) that don't require a live database.
End-to-end DB tests live in the integration test suite.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas.analytics_platform import TimeRange
from app.services.analytics_platform.kpi_service import KPIService
from app.services.analytics_platform.security_score_service import (
    SecurityScoreService,
)
from app.services.analytics_platform.time_filters import TimeFilterService


_UTC = timezone.utc


def test_time_filter_last_7_days_span_is_seven_days():
    tf = TimeFilterService()
    tr = tf.resolve("last_7_days")
    assert (tr.until - tr.since).days >= 6
    assert tr.granularity == "day"


def test_time_filter_custom_requires_bounds():
    tf = TimeFilterService()
    try:
        tf.resolve("custom")
    except ValueError:
        return
    raise AssertionError("custom filter without bounds must raise")


def test_time_filter_previous_period_lengths_match():
    tf = TimeFilterService()
    tr = tf.resolve("last_30_days")
    prev = tf.previous_period(tr)
    assert abs((prev.until - prev.since).total_seconds()
               - (tr.until - tr.since).total_seconds()) < 5


def test_kpi_delta_and_trend_up():
    kpi = KPIService().card(key="k", label="Emails",
                             value=120, prev_value=100)
    assert kpi.delta_pct == 20.0
    assert kpi.trend == "up"


def test_kpi_lower_is_better_flips_trend():
    kpi = KPIService().card(key="k", label="Threats",
                             value=8, prev_value=4, higher_is_better=False)
    assert kpi.trend == "up" is False  # sanity: not "up" — should be "down"
    assert kpi.trend == "down"


def test_security_score_high_when_clean_inbox():
    s = SecurityScoreService()
    card = s.security_score(total_scanned=1000, threats_detected=5,
                            blocked=5, recent_critical=0)
    assert card.score >= 85
    assert card.band in ("good", "excellent")


def test_security_score_low_when_many_threats():
    s = SecurityScoreService()
    card = s.security_score(total_scanned=100, threats_detected=60,
                            blocked=10, recent_critical=6)
    assert card.score <= 60


def test_threat_score_pressure_scales():
    s = SecurityScoreService()
    card = s.threat_score(total_scanned=100, threats_detected=90,
                          critical_count=5)
    assert card.score >= 80


def test_protection_pct_defaults_to_100_when_no_threats():
    s = SecurityScoreService()
    assert s.protection_pct(threats=0, blocked=0) == 100.0


def test_safe_ratio_bounds():
    s = SecurityScoreService()
    assert s.safe_ratio(total=0, threats=0) == 1.0
    assert 0.0 <= s.safe_ratio(total=100, threats=25) <= 1.0
