"""Redis key namespace for the Threat Intelligence Engine."""
from __future__ import annotations

NS = "gm:threat"


def scan_lock(email_id: str) -> str:
    return f"{NS}:lock:email:{email_id}"


def recheck_lock(report_id: str) -> str:
    return f"{NS}:lock:recheck:{report_id}"


def provider_circuit(provider: str) -> str:
    return f"{NS}:circuit:{provider}"


def provider_ratelimit(provider: str, window: str) -> str:
    return f"{NS}:ratelimit:{provider}:{window}"


def cache_key(provider: str, artifact_hash: str) -> str:
    return f"{NS}:cache:{provider}:{artifact_hash}"


def dedupe_url_scan(url_hash: str) -> str:
    return f"{NS}:dedupe:url:{url_hash}"
