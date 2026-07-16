"""Single clock — inject in tests, never use datetime.utcnow directly."""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def epoch_ms() -> int:
    return int(now_utc().timestamp() * 1000)
