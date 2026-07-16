"""DomainIntelligenceService — typosquatting, homograph, TLD/registrar risk.

Deterministic, dependency-light heuristics. Real-time WHOIS/DNS lookups
belong to Module 15 (Threat Intel); this service focuses on structural
signals that can be derived from the domain string alone.
"""
from __future__ import annotations

import re
from typing import Any

_SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "ml", "tk",
    "cf", "kim", "work", "loan", "review", "party",
}
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "tempmail.com", "yopmail.com", "trashmail.com",
}
_BRAND_TARGETS = (
    "paypal", "microsoft", "google", "apple", "amazon", "facebook",
    "instagram", "netflix", "chase", "wellsfargo", "bankofamerica",
    "docusign", "dhl", "fedex", "ups", "linkedin", "office365",
    "outlook", "onedrive", "dropbox",
)
_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1,
                           prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


class DomainIntelligenceService:
    def analyze(self, domain: str | None) -> dict[str, Any]:
        d = (domain or "").strip().lower().lstrip("@")
        if not d or "." not in d:
            return {"domain": d, "score": 0, "flags": ["missing_domain"]}

        flags: list[str] = []
        score = 0.0

        # Unicode / punycode
        try:
            d.encode("ascii")
        except UnicodeEncodeError:
            flags.append("unicode_domain")
            score += 25
        if d.startswith("xn--"):
            flags.append("punycode_domain")
            score += 20

        tld = d.rsplit(".", 1)[-1]
        if tld in _SUSPICIOUS_TLDS:
            flags.append(f"suspicious_tld:{tld}")
            score += 15

        if d in _DISPOSABLE_DOMAINS:
            flags.append("disposable_domain")
            score += 25

        # Excess subdomain nesting (>3 labels) or long random label
        labels = d.split(".")
        if len(labels) > 4:
            flags.append("deep_subdomains")
            score += 10
        if any(len(lbl) > 25 and re.match(r"^[a-z0-9\-]+$", lbl) for lbl in labels):
            flags.append("random_looking_label")
            score += 10

        # Digit / hyphen density
        if sum(c.isdigit() for c in d) >= max(3, len(d) // 5):
            flags.append("digit_heavy")
            score += 5
        if d.count("-") >= 3:
            flags.append("hyphen_heavy")
            score += 5

        # Typosquat / lookalike against known brands
        core = labels[-2] if len(labels) >= 2 else d
        normalised = core.translate(_CONFUSABLE)
        for brand in _BRAND_TARGETS:
            if brand == core:
                continue
            if brand in core and core != brand:
                flags.append(f"brand_in_subdomain:{brand}")
                score += 20
                break
            dist = _levenshtein(normalised, brand)
            if 0 < dist <= 2 and abs(len(normalised) - len(brand)) <= 2:
                flags.append(f"typosquat:{brand}")
                score += 25
                break

        return {
            "domain": d,
            "flags": flags,
            "score": min(70.0, score),
            "tld": tld,
        }


domain_intelligence_service = DomainIntelligenceService()
