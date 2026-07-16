"""Local heuristic detection engine.

Deterministic, dependency-free signals that raise confidence even when no
external provider reports the artifact.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import tldextract

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
    "tiny.cc", "rb.gy", "shorturl.at", "cli.gs", "s.id",
}

# Common brands that phishing pages impersonate.
BRAND_TARGETS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "github",
    "bankofamerica", "chase", "wellsfargo", "hsbc", "santander",
    "dhl", "fedex", "usps", "irs", "hmrc",
}

URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediate|verify (?:now|account)|suspended|action required|"
    r"limited time|final notice|password (?:expired|reset)|"
    r"unauthorized (?:access|login)|click here now|confirm identity)\b",
    re.I,
)

CREDENTIAL_PATTERNS = re.compile(
    r"\b(login|sign[- ]?in|password|otp|one[- ]time (?:code|password)|"
    r"account (?:locked|suspended)|verify (?:your )?(?:email|phone|identity))\b",
    re.I,
)

BEC_PATTERNS = re.compile(
    r"\b(wire transfer|change (?:of )?(?:bank|account)|invoice attached|"
    r"payment overdue|new banking details|urgent payment)\b",
    re.I,
)

EXECUTABLE_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".jar", ".msi", ".apk", ".dll",
}

MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpg|png)\.[a-z0-9]{2,4}$", re.I)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                curr[-1] + 1,
                prev[j] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = curr
    return prev[-1]


def _has_unicode_confusables(s: str) -> bool:
    return any(ord(ch) > 127 for ch in s)


def _homograph_or_typosquat(domain: str) -> tuple[bool, str | None]:
    core = domain.split(".")[0].lower() if domain else ""
    if not core:
        return False, None
    if _has_unicode_confusables(core):
        return True, "unicode_confusables"
    for brand in BRAND_TARGETS:
        d = _levenshtein(core, brand)
        if 0 < d <= 2 and core != brand:
            return True, f"typosquat_of:{brand}"
    return False, None


def analyze_url(url: str) -> list[dict[str, Any]]:
    """Return heuristic indicators for a single URL."""
    indicators: list[dict[str, Any]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return [{"category": "url", "severity": "medium",
                 "detail": "malformed url"}]
    host = (parsed.hostname or "").lower()
    ext = tldextract.extract(url)
    dom = ext.registered_domain

    if parsed.scheme != "https":
        indicators.append({"category": "transport", "severity": "medium",
                           "detail": "non-https link"})
    if dom in SHORTENER_DOMAINS or host in SHORTENER_DOMAINS:
        indicators.append({"category": "url", "severity": "medium",
                           "detail": f"url shortener: {dom or host}"})
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        indicators.append({"category": "url", "severity": "high",
                           "detail": "raw IP address in URL"})
    if parsed.port and parsed.port not in (80, 443):
        indicators.append({"category": "url", "severity": "medium",
                           "detail": f"non-standard port {parsed.port}"})
    if len(host) > 60:
        indicators.append({"category": "url", "severity": "low",
                           "detail": "unusually long hostname"})
    if host.count("-") >= 3:
        indicators.append({"category": "url", "severity": "low",
                           "detail": "many hyphens in hostname"})

    homo, why = _homograph_or_typosquat(ext.domain)
    if homo:
        indicators.append({"category": "domain", "severity": "high",
                           "detail": why or "homograph/typosquat"})

    return indicators


def analyze_text(text: str) -> list[dict[str, Any]]:
    """Body / OCR text heuristics: urgency, credential harvest, BEC."""
    out: list[dict[str, Any]] = []
    if not text:
        return out
    if URGENCY_PATTERNS.search(text):
        out.append({"category": "language", "severity": "medium",
                    "detail": "urgency language"})
    if CREDENTIAL_PATTERNS.search(text):
        out.append({"category": "language", "severity": "high",
                    "detail": "credential-harvesting language"})
    if BEC_PATTERNS.search(text):
        out.append({"category": "language", "severity": "high",
                    "detail": "business email compromise pattern"})
    if re.search(r"data:image/[a-z]+;base64,", text or ""):
        out.append({"category": "content", "severity": "low",
                    "detail": "inline base64 image"})
    return out


def analyze_attachment(att: dict[str, Any]) -> list[dict[str, Any]]:
    name = (att.get("name") or "").lower()
    mime = (att.get("mime") or "").lower()
    out: list[dict[str, Any]] = []
    for ext_ in EXECUTABLE_EXTS:
        if name.endswith(ext_):
            out.append({"category": "attachment", "severity": "critical",
                        "detail": f"executable extension {ext_}"})
            break
    for ext_ in MACRO_EXTS:
        if name.endswith(ext_):
            out.append({"category": "attachment", "severity": "high",
                        "detail": f"macro-enabled office file {ext_}"})
            break
    if DOUBLE_EXT_RE.search(name):
        out.append({"category": "attachment", "severity": "high",
                    "detail": "double-extension filename"})
    if att.get("password_protected"):
        out.append({"category": "attachment", "severity": "high",
                    "detail": "password-protected archive"})
    if mime.startswith("application/x-msdownload"):
        out.append({"category": "attachment", "severity": "critical",
                    "detail": "windows executable MIME"})
    return out


def analyze_email_auth(auth: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not auth:
        return []
    out: list[dict[str, Any]] = []
    for key in ("spf", "dkim", "dmarc"):
        v = str(auth.get(key, "")).lower()
        if v in ("fail", "softfail", "none", "temperror", "permerror"):
            out.append({"category": "email_auth", "severity": "high",
                        "detail": f"{key.upper()} {v}"})
    return out
