"""Redis key namespaces for the AI engine."""
from __future__ import annotations


def ai_lock_key(threat_report_id: str) -> str:
    return f"ai:lock:{threat_report_id}"


def ai_cache_key(prompt_hash: str) -> str:
    return f"ai:cache:{prompt_hash}"


def ai_rate_key(user_id: str, bucket: str) -> str:
    return f"ai:rate:{user_id}:{bucket}"
