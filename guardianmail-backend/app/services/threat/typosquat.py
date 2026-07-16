"""Typosquat / look-alike domain detection.

Two independent signals feed the engine:

* `damerau_levenshtein_ratio` — near-neighbour edit distance against a
  small set of protected brands. Cheap and language-agnostic.
* `looks_like_brand` — combines edit distance with a homograph check
  (Cyrillic/Greek characters visually resembling ASCII).

The check runs against the *registered domain* (e.g. `paypa1.com`),
not the FQDN, so subdomain padding (`login.paypal.com.attacker.ru`)
still hits the correct brand.
"""
from __future__ import annotations

from app.services.threat.config import PROTECTED_BRANDS
from app.services.threat.normalizer import (
    contains_mixed_scripts,
    is_idn,
    registered_domain,
)

# Confusable pairs (subset — extended over time).
_CONFUSABLES = {
    "0": "o", "1": "l", "5": "s", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",  # Cyrillic
    "α": "a", "ο": "o", "ρ": "p",                       # Greek
}


def _fold_confusables(s: str) -> str:
    return "".join(_CONFUSABLES.get(ch, ch) for ch in s.lower())


def damerau_levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return la or lb
    # Two-row DL — O(la*lb) time, O(lb) space.
    prev2 = [0] * (lb + 1)
    prev = list(range(lb + 1))
    curr = [0] * (lb + 1)
    for i in range(1, la + 1):
        curr[0] = i
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
            if (
                i > 1 and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                curr[j] = min(curr[j], prev2[j - 2] + 1)  # transposition
        prev2, prev, curr = prev, curr, prev2
    return prev[lb]


def similarity_ratio(a: str, b: str) -> float:
    """1.0 identical → 0.0 completely different."""
    if not a or not b:
        return 0.0
    m = max(len(a), len(b))
    return 1.0 - (damerau_levenshtein(a, b) / m)


def looks_like_brand(domain: str, *, brands: frozenset[str] = PROTECTED_BRANDS) -> tuple[str | None, float, bool]:
    """Return (matched_brand, similarity, homograph_flag)."""
    reg = registered_domain(domain) or domain.lower()
    if reg in brands:
        return reg, 1.0, False
    folded = _fold_confusables(reg)
    best: tuple[str | None, float] = (None, 0.0)
    for brand in brands:
        r = similarity_ratio(folded, brand)
        if r > best[1]:
            best = (brand, r)
    matched, score = best
    homograph = is_idn(reg) or contains_mixed_scripts(reg) or folded != reg
    # Only flag when close enough but not identical, or when there is a
    # visual (confusables/idn) trick even at lower edit distance.
    if matched and 0.75 <= score < 1.0:
        return matched, score, homograph
    if matched and homograph and score >= 0.6:
        return matched, score, homograph
    return None, score, homograph
