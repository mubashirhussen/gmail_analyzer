"""Redis key builders for the OCR engine (locks + dedup)."""
from __future__ import annotations

NS = "ocr"


def upload_dedup(user_id: str, sha256: str) -> str:
    """Short TTL — coalesces concurrent uploads of the same bytes."""
    return f"{NS}:dedup:{user_id}:{sha256}"


def processing_lock(report_id: str) -> str:
    return f"{NS}:lock:report:{report_id}"


def user_rate(user_id: str) -> str:
    return f"{NS}:rate:{user_id}"
