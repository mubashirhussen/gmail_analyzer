"""Subscription lifecycle (Phase 20)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.services.saas.plans import PLANS, PlanLimits, get_plan


VALID_STATUS = {"trialing", "active", "past_due", "canceled", "expired"}


class SubscriptionService:
    def __init__(self, repository=None):
        self.repo = repository

    def build(self, *, tenant_id: str, plan: str = "free",
              billing_cycle: str = "monthly", trial_days: int = 0,
              seats: int = 1) -> dict:
        if plan not in PLANS:
            raise ValueError(f"invalid plan: {plan}")
        if billing_cycle not in {"monthly", "annual"}:
            raise ValueError("billing_cycle must be monthly|annual")
        if seats < 1:
            raise ValueError("seats must be >= 1")

        now = datetime.now(timezone.utc)
        if trial_days > 0:
            status = "trialing"
            current_period_end = now + timedelta(days=trial_days)
        else:
            status = "active"
            days = 30 if billing_cycle == "monthly" else 365
            current_period_end = now + timedelta(days=days)

        return {
            "subscription_id": f"sub_{uuid.uuid4().hex[:20]}",
            "tenant_id": tenant_id,
            "plan": plan,
            "billing_cycle": billing_cycle,
            "seats": seats,
            "status": status,
            "trial_days": trial_days,
            "current_period_start": now,
            "current_period_end": current_period_end,
            "created_at": now,
            "updated_at": now,
        }

    # -- lifecycle -----------------------------------------------------
    def change_plan(self, subscription: dict, new_plan: str) -> dict:
        if new_plan not in PLANS:
            raise ValueError(f"invalid plan: {new_plan}")
        subscription["plan"] = new_plan
        subscription["updated_at"] = datetime.now(timezone.utc)
        return subscription

    def cancel(self, subscription: dict, *, at_period_end: bool = True) -> dict:
        now = datetime.now(timezone.utc)
        if at_period_end:
            subscription["cancel_at_period_end"] = True
        else:
            subscription["status"] = "canceled"
            subscription["canceled_at"] = now
        subscription["updated_at"] = now
        return subscription

    def renew(self, subscription: dict) -> dict:
        now = datetime.now(timezone.utc)
        days = 30 if subscription.get("billing_cycle") == "monthly" else 365
        subscription["current_period_start"] = now
        subscription["current_period_end"] = now + timedelta(days=days)
        subscription["status"] = "active"
        subscription["updated_at"] = now
        return subscription

    @staticmethod
    def limits(subscription: dict) -> PlanLimits:
        return get_plan(subscription.get("plan", "free"))

    @staticmethod
    def is_active(subscription: dict, *, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if subscription.get("status") not in {"active", "trialing"}:
            return False
        end = subscription.get("current_period_end")
        return not end or end > now

    @staticmethod
    def feature_enabled(subscription: dict, feature: str) -> bool:
        feats = get_plan(subscription.get("plan", "free")).features
        return "*" in feats or feature in feats
