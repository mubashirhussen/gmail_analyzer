"""Retention helpers (Phase 20)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

_ALLOWED = {30, 90, 180, 365, -1}  # -1 == forever


def normalize_retention(days: int) -> int:
    if days not in _ALLOWED:
        raise ValueError(f"unsupported retention window: {days}")
    return days


def cutoff(days: int, *, now: datetime | None = None) -> datetime | None:
    if days == -1:
        return None
    now = now or datetime.now(timezone.utc)
    return now - timedelta(days=days)
