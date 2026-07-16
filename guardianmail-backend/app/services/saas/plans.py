"""Subscription plan catalogue (Phase 20).

Immutable definitions used by SubscriptionService, QuotaService, and
BillingService. Values chosen conservatively; production overrides can be
supplied via env-driven overrides without editing this file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class PlanLimits:
    storage_mb: int
    monthly_scans: int
    daily_scans: int
    users: int
    organizations: int
    ocr_monthly: int
    ai_monthly: int
    threat_intel_monthly: int
    complaints_monthly: int
    api_calls_daily: int
    retention_days: int
    features: tuple = field(default_factory=tuple)


PLANS: Dict[str, PlanLimits] = {
    "free": PlanLimits(
        storage_mb=100, monthly_scans=100, daily_scans=25, users=1,
        organizations=1, ocr_monthly=25, ai_monthly=25,
        threat_intel_monthly=50, complaints_monthly=5,
        api_calls_daily=200, retention_days=30,
        features=("dashboard", "threat_scan"),
    ),
    "starter": PlanLimits(
        storage_mb=1024, monthly_scans=2_000, daily_scans=500, users=5,
        organizations=1, ocr_monthly=500, ai_monthly=500,
        threat_intel_monthly=1_000, complaints_monthly=50,
        api_calls_daily=2_000, retention_days=90,
        features=("dashboard", "threat_scan", "ai_copilot", "complaints"),
    ),
    "professional": PlanLimits(
        storage_mb=10_240, monthly_scans=20_000, daily_scans=3_000, users=25,
        organizations=3, ocr_monthly=5_000, ai_monthly=5_000,
        threat_intel_monthly=10_000, complaints_monthly=500,
        api_calls_daily=20_000, retention_days=180,
        features=("dashboard", "threat_scan", "ai_copilot", "complaints",
                  "analytics", "api"),
    ),
    "business": PlanLimits(
        storage_mb=51_200, monthly_scans=100_000, daily_scans=15_000, users=100,
        organizations=10, ocr_monthly=25_000, ai_monthly=25_000,
        threat_intel_monthly=50_000, complaints_monthly=2_500,
        api_calls_daily=100_000, retention_days=365,
        features=("dashboard", "threat_scan", "ai_copilot", "complaints",
                  "analytics", "api", "soc", "sso"),
    ),
    "enterprise": PlanLimits(
        storage_mb=512_000, monthly_scans=1_000_000, daily_scans=100_000,
        users=1_000, organizations=100, ocr_monthly=250_000, ai_monthly=250_000,
        threat_intel_monthly=500_000, complaints_monthly=25_000,
        api_calls_daily=1_000_000, retention_days=730,
        features=("dashboard", "threat_scan", "ai_copilot", "complaints",
                  "analytics", "api", "soc", "sso", "audit_export",
                  "custom_roles", "priority_support"),
    ),
    "custom": PlanLimits(
        storage_mb=-1, monthly_scans=-1, daily_scans=-1, users=-1,
        organizations=-1, ocr_monthly=-1, ai_monthly=-1,
        threat_intel_monthly=-1, complaints_monthly=-1,
        api_calls_daily=-1, retention_days=-1,
        features=("*",),
    ),
}


def get_plan(name: str) -> PlanLimits:
    key = (name or "free").lower()
    if key not in PLANS:
        raise ValueError(f"unknown plan: {name}")
    return PLANS[key]


def is_unlimited(value: int) -> bool:
    return value is not None and value < 0
