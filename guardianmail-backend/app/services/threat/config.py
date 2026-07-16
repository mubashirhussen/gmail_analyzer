"""Threat Intelligence Engine — tunables.

All weights, thresholds, timeouts, and TTLs live here as a single source
of truth. Nothing in the engine should hard-code a numeric constant. Ops
can override any value via env (`THREAT_*`) without editing code.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

# ---------------------------------------------------------------- providers
# Cache TTLs (seconds). Kept short enough that a re-scan after a widespread
# incident sees new provider signal, long enough to protect API quotas.
PROVIDER_CACHE_TTL = {
    "google_safe_browsing": 3600,   # 1h — Google publishes fast
    "virustotal": 6 * 3600,         # 6h — quota-heavy
    "urlscan": 12 * 3600,           # 12h — public scans age slowly
    "phishtank": 24 * 3600,
    "urlhaus": 24 * 3600,
    "rdap": 7 * 24 * 3600,          # WHOIS rarely changes
    "abuseipdb": 6 * 3600,
    "dns": 30 * 60,                 # 30min
    "ssl": 6 * 3600,
}

PROVIDER_TIMEOUT_S = {
    "google_safe_browsing": 6.0,
    "virustotal": 8.0,
    "urlscan": 8.0,
    "phishtank": 6.0,
    "urlhaus": 6.0,
    "rdap": 5.0,
    "abuseipdb": 6.0,
    "dns": 4.0,
    "ssl": 6.0,
}

PROVIDER_MAX_RETRIES = 2  # per scan; scheduler adds outer retries


# ------------------------------------------------------------------ scoring
class ScoreWeights(BaseModel):
    """Signal weights that combine into `threat_score`.

    All weights are additive contributions to a 0..100 scale, capped at
    100. Kept as a model so ops can override individual fields via env
    without touching the aggregator code.
    """

    # url / domain intel
    url_malicious_provider: float = 45.0
    url_suspicious_provider: float = 22.0
    domain_new: float = 10.0                # < 30 days
    domain_very_new: float = 18.0           # < 7 days
    domain_risky_tld: float = 6.0
    domain_disposable: float = 8.0
    domain_typosquat: float = 20.0
    domain_homograph: float = 22.0

    # ssl / dns
    ssl_expired: float = 8.0
    ssl_self_signed: float = 6.0
    dns_no_mx: float = 4.0

    # email auth
    spf_fail: float = 12.0
    dkim_fail: float = 12.0
    dmarc_fail: float = 15.0
    dmarc_missing: float = 6.0
    reply_to_mismatch: float = 10.0
    return_path_mismatch: float = 8.0
    display_name_mismatch: float = 12.0

    # headers
    forged_received: float = 14.0
    timestamp_anomaly: float = 4.0

    # attachments
    attachment_executable: float = 25.0
    attachment_double_ext: float = 18.0
    attachment_macro_office: float = 20.0
    attachment_encrypted_archive: float = 15.0
    attachment_known_malware_hash: float = 60.0

    # ip
    ip_blacklisted: float = 22.0
    ip_tor: float = 8.0
    ip_hosting: float = 4.0


# ------------------------------------------------------------- verdict bands
def band(score: float) -> Literal["safe", "low_risk", "medium_risk", "high_risk", "critical"]:
    if score < 15:
        return "safe"
    if score < 35:
        return "low_risk"
    if score < 60:
        return "medium_risk"
    if score < 85:
        return "high_risk"
    return "critical"


RECOMMENDED_ACTION = {
    "safe": "allow",
    "low_risk": "monitor",
    "medium_risk": "warn_user",
    "high_risk": "quarantine",
    "critical": "block",
}


# ------------------------------------------------------------- risky metadata
# Non-exhaustive; extended at runtime from threat feeds. Kept small and
# curated so the engine has a sane default when feeds are cold.
RISKY_TLDS = frozenset({
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "cf", "tk", "ml", "top", "xyz", "click", "link",
    "loan", "download", "stream", "racing", "date", "faith", "men",
})

DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwawaymail.com", "yopmail.com", "getnada.com",
    "sharklasers.com", "trashmail.com", "maildrop.cc",
})

# Popular brands we protect against typosquat/homograph. Extended
# per-tenant via `trusted_brands` (module 6 hook).
PROTECTED_BRANDS = frozenset({
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "office.com", "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "facebook.com", "instagram.com", "linkedin.com", "netflix.com",
    "github.com", "dropbox.com", "adobe.com", "docusign.com",
    "chase.com", "hsbc.com", "sbi.co.in", "hdfcbank.com", "icicibank.com",
})

EXECUTABLE_EXTS = frozenset({
    "exe", "scr", "bat", "cmd", "com", "cpl", "msi", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "jar", "apk",
    "dll", "sys",
})

OFFICE_MACRO_EXTS = frozenset({
    "docm", "dotm", "xlsm", "xltm", "pptm", "potm",
})

ARCHIVE_EXTS = frozenset({"zip", "rar", "7z", "tar", "gz", "bz2", "iso", "cab"})
