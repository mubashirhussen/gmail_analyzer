"""Quota enforcement (Phase 20)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.services.saas.plans import PlanLimits, is_unlimited
from app.services.saas.usage_service import UsageService


@dataclass
class QuotaResult:
    allowed: bool
    metric: str
    limit: int
    used: int
    remaining: int
    reason: Optional[str] = None


_DAILY_MAP = {
    "threat_scans": ("daily_scans", UsageService.today),
    "emails_scanned": ("daily_scans", UsageService.today),
    "api_calls": ("api_calls_daily", UsageService.today),
}

_MONTHLY_MAP = {
    "threat_scans": ("monthly_scans", UsageService.month),
    "emails_scanned": ("monthly_scans", UsageService.month),
    "ocr_requests": ("ocr_monthly", UsageService.month),
    "ai_requests": ("ai_monthly", UsageService.month),
    "complaint_generations": ("complaints_monthly", UsageService.month),
}


class QuotaService:
    def __init__(self, usage: UsageService):
        self.usage = usage

    def _check_one(self, tenant_id: str, metric: str, limit: int,
                   period: str, amount: int) -> QuotaResult:
        if is_unlimited(limit):
            return QuotaResult(True, metric, -1, -1, -1)
        used = self.usage.get(tenant_id, metric, period)
        remaining = max(limit - used, 0)
        allowed = (used + amount) <= limit
        return QuotaResult(
            allowed=allowed, metric=metric, limit=limit,
            used=used, remaining=remaining,
            reason=None if allowed else f"{metric} quota exceeded",
        )

    def check(self, tenant_id: str, metric: str, limits: PlanLimits,
              amount: int = 1) -> QuotaResult:
        # Enforce the strictest applicable window first.
        for mapping in (_DAILY_MAP, _MONTHLY_MAP):
            if metric in mapping:
                attr, period_fn = mapping[metric]
                lim = getattr(limits, attr)
                res = self._check_one(tenant_id, metric, lim, period_fn(), amount)
                if not res.allowed:
                    return res
        # Storage cap is a level, not a delta window.
        if metric == "storage_mb":
            used = self.usage.get(tenant_id, metric, UsageService.month())
            lim = limits.storage_mb
            if not is_unlimited(lim) and (used + amount) > lim:
                return QuotaResult(False, metric, lim, used,
                                   max(lim - used, 0), "storage quota exceeded")
        return QuotaResult(True, metric, -1, 0, -1)

    def consume(self, tenant_id: str, metric: str, limits: PlanLimits,
                amount: int = 1) -> QuotaResult:
        result = self.check(tenant_id, metric, limits, amount)
        if result.allowed:
            self.usage.record(tenant_id, metric, amount)
        return result
