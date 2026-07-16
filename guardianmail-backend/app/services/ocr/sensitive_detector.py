"""Sensitive-data detection: PII, credentials, secrets.

Detected values are *never* stored raw. We only persist:

* per-category counts (for analytics), and
* a small number of masked previews (last 4 chars) so the user can identify
  which line triggered the finding.

Luhn is used to filter card-shaped noise. JWT/PEM/AWS/Azure/Google patterns
match structural anchors, not entropy — cheap and deterministic.
"""
from __future__ import annotations

import re
from collections import defaultdict

from app.models.ocr_report import SensitiveSummary

_MAX_SAMPLES = 3

CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
UPI_RE = re.compile(r"\b[A-Z0-9._\-]{2,64}@[A-Z]{2,64}\b", re.IGNORECASE)  # naive; cross-checked
AADHAAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
PASSPORT_RE = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6}\b")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_RE = re.compile(r"\baws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}\b", re.IGNORECASE)
GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
AZURE_KEY_RE = re.compile(r"\b[A-Za-z0-9+/]{88}==\b")  # base64 of 64 bytes
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----")
PASSWORD_RE = re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*(\S{6,})", re.IGNORECASE)
API_KEY_RE = re.compile(r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", re.IGNORECASE)


def _luhn(digits: str) -> bool:
    n = [int(c) for c in digits if c.isdigit()]
    if len(n) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(n)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(value: str, keep: int = 4) -> str:
    v = value.strip()
    if len(v) <= keep:
        return "*" * len(v)
    return "*" * (len(v) - keep) + v[-keep:]


def detect(text: str) -> SensitiveSummary:
    if not text:
        return SensitiveSummary()

    counts: dict[str, int] = defaultdict(int)
    samples: dict[str, list[str]] = defaultdict(list)

    def _push(kind: str, value: str) -> None:
        counts[kind] += 1
        if len(samples[kind]) < _MAX_SAMPLES:
            samples[kind].append(_mask(value))

    for m in CARD_RE.findall(text):
        digits = re.sub(r"\D", "", m)
        if _luhn(digits):
            _push("credit_card", digits)

    for m in IBAN_RE.findall(text):
        _push("iban", m)
    for m in AADHAAR_RE.findall(text):
        _push("aadhaar", m)
    for m in PAN_RE.findall(text):
        _push("pan", m)
    for m in PASSPORT_RE.findall(text):
        _push("passport", m)
    for m in JWT_RE.findall(text):
        _push("jwt", m)
    for m in AWS_KEY_RE.findall(text):
        _push("aws_access_key", m)
    for _ in AWS_SECRET_RE.findall(text):
        counts["aws_secret_key"] += 1
    for m in GOOGLE_KEY_RE.findall(text):
        _push("google_api_key", m)
    for m in AZURE_KEY_RE.findall(text):
        _push("azure_key", m)
    if PRIVATE_KEY_RE.search(text):
        counts["private_key"] += 1
        samples["private_key"].append("-----BEGIN … PRIVATE KEY-----")
    for m in PASSWORD_RE.findall(text):
        _push("password", m)
    for m in API_KEY_RE.findall(text):
        _push("api_key", m)

    # UPI: filter to well-known PSP handles to reduce false positives
    upi_psps = {"okhdfcbank", "okicici", "okaxis", "oksbi", "ybl", "paytm", "upi", "ibl", "axl"}
    for m in UPI_RE.findall(text):
        try:
            psp = m.split("@", 1)[1].lower()
        except IndexError:
            continue
        if psp in upi_psps:
            _push("upi", m)

    return SensitiveSummary(counts=dict(counts), samples={k: v for k, v in samples.items()})
