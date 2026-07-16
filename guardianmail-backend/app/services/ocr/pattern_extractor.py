"""Regex-based extraction of security-relevant patterns from text.

Runs after text extraction — deterministic, side-effect free, and reused by
the sensitive-data detector for overlapping patterns (credit cards etc.).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models.ocr_report import ExtractedPatterns

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s\-.])?(?:\(?\d{2,4}\)?[\s\-.])?\d{3,4}[\s\-.]?\d{3,4}"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DATE_RE = re.compile(
    r"\b(?:\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b",
    re.IGNORECASE,
)
AMOUNT_RE = re.compile(
    r"(?:USD|INR|EUR|GBP|₹|\$|€|£)\s?\d{1,3}(?:[,\d]{0,12})(?:\.\d{1,2})?",
    re.IGNORECASE,
)
INVOICE_RE = re.compile(r"\b(?:invoice|inv|bill)[\s#:.\-]*([A-Z0-9\-]{4,20})\b", re.IGNORECASE)
TRACKING_RE = re.compile(r"\b(?:tracking|awb|consignment)[\s#:.\-]*([A-Z0-9\-]{6,30})\b", re.IGNORECASE)
REF_RE = re.compile(r"\b(?:ref(?:erence)?|txn|transaction)[\s#:.\-]*([A-Z0-9\-]{5,30})\b", re.IGNORECASE)
ACCT_RE = re.compile(r"\b(?:a/?c|account)\s*(?:no\.?|number|#)?\s*[:\-]?\s*(\d{6,18})\b", re.IGNORECASE)


def _dedup(items: list[str], limit: int = 200) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        v = it.strip().rstrip(".,);:>]")
        if v and v not in seen:
            seen[v] = None
            if len(seen) >= limit:
                break
    return list(seen)


def _mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def extract_patterns(text: str) -> ExtractedPatterns:
    if not text:
        return ExtractedPatterns()

    urls = _dedup(URL_RE.findall(text))
    emails = _dedup(EMAIL_RE.findall(text))
    ips = _dedup(IPV4_RE.findall(text))
    dates = _dedup(DATE_RE.findall(text), limit=50)
    amounts = _dedup(AMOUNT_RE.findall(text), limit=50)
    invoices = _dedup(INVOICE_RE.findall(text), limit=25)
    tracking = _dedup(TRACKING_RE.findall(text), limit=25)
    refs = _dedup(REF_RE.findall(text), limit=25)
    accounts = _dedup([_mask(a) for a in ACCT_RE.findall(text)], limit=25)

    # phone numbers are noisy — bound + de-dup and drop obvious noise
    phones = []
    for p in PHONE_RE.findall(text)[:200]:
        digits = re.sub(r"\D", "", p)
        if 8 <= len(digits) <= 15:
            phones.append(p.strip())
    phones = _dedup(phones, limit=40)

    domains: list[str] = []
    for u in urls:
        try:
            host = urlparse(u).hostname
            if host:
                domains.append(host.lower())
        except Exception:
            continue
    domains = _dedup(domains, limit=100)

    return ExtractedPatterns(
        urls=urls,
        domains=domains,
        emails=emails,
        phones=phones,
        ips=ips,
        dates=dates,
        amounts=amounts,
        account_numbers=accounts,
        reference_ids=refs,
        invoice_numbers=invoices,
        tracking_numbers=tracking,
    )
