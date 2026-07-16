"""Billing abstraction (Phase 20).

Provider-agnostic invoice + charge modeling. The `Provider` protocol is
where Stripe / Razorpay / PayPal / enterprise-invoicing adapters plug in;
none are implemented here to keep this module dependency-free.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional, Protocol


class BillingProvider(Protocol):
    name: str

    def create_charge(self, invoice: dict) -> dict: ...  # pragma: no cover


class BillingService:
    # Rate cards — cents, base plan (before usage).
    _PLAN_CENTS = {
        "free": 0,
        "starter": 1_900,
        "professional": 4_900,
        "business": 19_900,
        "enterprise": 99_900,
        "custom": 0,
    }
    # Overage rates in cents per unit (post-quota).
    _OVERAGE = {
        "emails_scanned": 1,
        "ai_requests": 3,
        "ocr_requests": 2,
        "threat_intel_requests": 1,
    }

    def __init__(self, provider: Optional[BillingProvider] = None):
        self.provider = provider

    # -- invoices ------------------------------------------------------
    def build_invoice(self, *, tenant_id: str, subscription_id: str,
                      plan: str, period_start: datetime,
                      period_end: datetime,
                      overage: Optional[dict] = None,
                      coupon_percent: int = 0,
                      currency: str = "USD") -> dict:
        if plan not in self._PLAN_CENTS:
            raise ValueError(f"invalid plan: {plan}")
        if not 0 <= coupon_percent <= 100:
            raise ValueError("coupon_percent must be within 0..100")

        line_items = [{
            "description": f"{plan.capitalize()} plan subscription",
            "quantity": 1,
            "unit_cents": self._PLAN_CENTS[plan],
            "amount_cents": self._PLAN_CENTS[plan],
        }]
        for metric, qty in (overage or {}).items():
            rate = self._OVERAGE.get(metric)
            if not rate or qty <= 0:
                continue
            line_items.append({
                "description": f"Overage: {metric}",
                "quantity": int(qty),
                "unit_cents": rate,
                "amount_cents": int(qty) * rate,
            })

        subtotal = sum(li["amount_cents"] for li in line_items)
        discount = subtotal * coupon_percent // 100
        total = subtotal - discount

        return {
            "invoice_id": f"inv_{uuid.uuid4().hex[:20]}",
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "currency": currency,
            "period_start": period_start,
            "period_end": period_end,
            "line_items": line_items,
            "subtotal_cents": subtotal,
            "discount_cents": discount,
            "total_cents": total,
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        }

    def apply_coupon(self, invoice: dict, percent: int) -> dict:
        if not 0 <= percent <= 100:
            raise ValueError("percent must be within 0..100")
        invoice["discount_cents"] = invoice["subtotal_cents"] * percent // 100
        invoice["total_cents"] = invoice["subtotal_cents"] - invoice["discount_cents"]
        return invoice

    def mark_paid(self, invoice: dict, *, reference: Optional[str] = None) -> dict:
        invoice["status"] = "paid"
        invoice["paid_at"] = datetime.now(timezone.utc)
        if reference:
            invoice["payment_reference"] = reference
        return invoice

    def void(self, invoice: dict) -> dict:
        invoice["status"] = "void"
        invoice["voided_at"] = datetime.now(timezone.utc)
        return invoice

    @staticmethod
    def total_billed(invoices: Iterable[dict]) -> int:
        return sum(
            int(inv.get("total_cents", 0))
            for inv in invoices if inv.get("status") == "paid"
        )
