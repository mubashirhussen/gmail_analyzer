"""Provider raw-response document.

Every call the Threat Intelligence Engine makes to an external provider
(VirusTotal, Google Safe Browsing, URLScan, PhishTank, URLHaus, RDAP,
AbuseIPDB, PhishTank, DNS/SSL probes, etc.) is persisted here.

Why a dedicated collection:
* replay & audit — we can reconstruct a report from raw provider payloads
  when logic changes.
* rate-limit accounting — TTL indexes on `expires_at` cap disk usage.
* cross-report intelligence — same URL asked twice within TTL reuses the
  cached row instead of burning API quota.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.models.base import Document

ArtifactKind = Literal["url", "domain", "ip", "file_hash", "email_addr", "header"]
ProviderStatus = Literal["ok", "skipped", "error", "timeout", "rate_limited", "unavailable"]


class ProviderResult(Document):
    # ---- attribution ----------------------------------------------------
    threat_report_id: str | None = None  # None while used purely as a cache row
    user_id: str | None = None

    provider: str  # canonical provider slug — 'virustotal', 'gsb', ...
    artifact_kind: ArtifactKind
    artifact_value: str  # canonical form (lowercased domain, sha256 hex...)
    artifact_hash: str  # sha256(artifact_value) — index target

    # ---- outcome --------------------------------------------------------
    status: ProviderStatus = "ok"
    verdict: Literal["clean", "suspicious", "malicious", "unknown"] = "unknown"
    score: float | None = None  # provider-native 0..1 or 0..100 (documented per provider)
    normalized_score: float = 0.0  # engine-normalized 0..100

    # ---- payload / diagnostics -----------------------------------------
    raw: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None

    # ---- caching --------------------------------------------------------
    expires_at: datetime | None = None  # TTL index target
