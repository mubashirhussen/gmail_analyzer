"""LanguageAnalysisService — urgency, coercion, credential / financial asks.

Rule-based lexicon so results are deterministic and auditable. AI-authored
scoring stays behind Module 6.
"""
from __future__ import annotations

import re
from typing import Any

_URGENCY = re.compile(
    r"\b(urgent|immediately|asap|right away|final notice|last warning|"
    r"within 24 hours|expires today|action required|act now|do not delay)\b",
    re.I,
)
_FEAR = re.compile(
    r"\b(suspend|suspended|locked|terminate|legal action|police|arrest|"
    r"account closure|penalty|fine|lawsuit|court)\b", re.I,
)
_CREDENTIALS = re.compile(
    r"\b(password|verify your account|confirm your identity|login credentials|"
    r"one[- ]time (code|password)|otp|two[- ]factor|reset your password|"
    r"click .{0,15}link .{0,15}verify)\b", re.I,
)
_FINANCE = re.compile(
    r"\b(wire transfer|bank transfer|swift|iban|routing number|invoice|"
    r"payment (due|overdue)|remit|remittance|payroll|change .{0,10}bank)\b",
    re.I,
)
_GIFT_CARD = re.compile(
    r"\b(gift card|itunes card|google play card|amazon card|steam card|"
    r"prepaid card)\b", re.I,
)
_CRYPTO = re.compile(
    r"\b(bitcoin|btc|ethereum|eth|usdt|crypto wallet|seed phrase|"
    r"cold wallet|blockchain)\b", re.I,
)
_ROMANCE = re.compile(
    r"\b(dear (my )?love|soulmate|god fearing|widow|inheritance|"
    r"transfer .{0,10}fund)\b", re.I,
)
_SUPPORT_SCAM = re.compile(
    r"\b(microsoft support|apple support|geek squad|virus detected|"
    r"call our support)\b", re.I,
)
_GOV = re.compile(
    r"\b(irs|hmrc|social security|ssn|department of|federal reserve|"
    r"immigration|uscis)\b", re.I,
)


CATEGORY_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("urgency", _URGENCY, 10),
    ("fear", _FEAR, 12),
    ("credential_request", _CREDENTIALS, 22),
    ("financial_request", _FINANCE, 18),
    ("gift_card", _GIFT_CARD, 25),
    ("crypto_scam", _CRYPTO, 20),
    ("romance_scam", _ROMANCE, 18),
    ("support_scam", _SUPPORT_SCAM, 22),
    ("government_impersonation", _GOV, 18),
]


class LanguageAnalysisService:
    def analyze(self, subject: str | None, body: str | None) -> dict[str, Any]:
        text = f"{subject or ''}\n{body or ''}"
        signals: list[dict[str, Any]] = []
        categories: list[str] = []
        score = 0.0
        for label, pat, weight in CATEGORY_PATTERNS:
            m = pat.search(text)
            if m:
                categories.append(label)
                signals.append({"kind": label, "match": m.group(0)[:60]})
                score += weight

        grammar = self._grammar_flags(text)
        if grammar:
            signals.append({"kind": "grammar", "flags": grammar})
            score += 5

        return {
            "categories": categories,
            "signals": signals,
            "score": min(80.0, score),
            "length": len(text),
        }

    @staticmethod
    def _grammar_flags(text: str) -> list[str]:
        flags: list[str] = []
        if "  " in text or "\n\n\n" in text:
            flags.append("whitespace_anomaly")
        # Mixed case / all-caps subjects
        words = re.findall(r"[A-Za-z]{4,}", text[:2000])
        if words and sum(1 for w in words if w.isupper()) / len(words) > 0.25:
            flags.append("caps_heavy")
        return flags


language_analysis_service = LanguageAnalysisService()
