"""KPI card assembly with previous-period delta.

`KPIService` is the only place that converts raw aggregate counts into
`KPICard` DTOs. Centralising this keeps units, rounding, and delta-arrow
logic consistent across every dashboard tile.
"""
from __future__ import annotations

from typing import Literal

from app.schemas.analytics_platform import KPICard

Trend = Literal["up", "down", "flat"]


def _delta_pct(cur: float, prev: float) -> float | None:
    if prev == 0:
        return None if cur == 0 else 100.0
    return round(((cur - prev) / prev) * 100.0, 2)


def _trend(cur: float, prev: float, *, higher_is_better: bool) -> Trend:
    if cur == prev:
        return "flat"
    up = cur > prev
    if higher_is_better:
        return "up" if up else "down"
    return "down" if up else "up"


class KPIService:
    def card(
        self,
        *,
        key: str,
        label: str,
        value: float,
        prev_value: float | None = None,
        unit: str | None = None,
        higher_is_better: bool = True,
        hint: str | None = None,
    ) -> KPICard:
        delta = _delta_pct(value, prev_value) if prev_value is not None else None
        trend: Trend = _trend(value, prev_value, higher_is_better=higher_is_better) \
            if prev_value is not None else "flat"
        return KPICard(
            key=key, label=label, value=round(value, 2),
            unit=unit, delta_pct=delta, trend=trend, hint=hint,
        )
