"""Derives educational guidance from AI output.

The service augments the LLM's `educational_tips` with curated,
verdict-specific guidance so users always receive at least one high
quality takeaway even when the model returns a sparse list.
"""
from __future__ import annotations

_GUIDANCE: dict[str, list[str]] = {
    "phishing": [
        "Legitimate services never ask you to confirm passwords via email links.",
        "Hover over links to preview the true destination before clicking.",
    ],
    "credential_theft": [
        "Enable multi-factor authentication on every important account.",
        "If you already submitted credentials, rotate the password immediately.",
    ],
    "business_email_compromise": [
        "Verify unusual payment or wire requests via a second channel (call, in person).",
        "Watch for subtle look-alike domains such as 'rn' replacing 'm'.",
    ],
    "invoice_fraud": [
        "Cross-check bank details with a known-good contact before paying invoices.",
        "Retain the original vendor's payment instructions on file.",
    ],
    "payment_scam": [
        "Never send money to a party you have not verified via a trusted channel.",
    ],
    "malware": [
        "Do not open unexpected attachments, even from trusted contacts.",
        "Keep your operating system and antivirus definitions up to date.",
    ],
    "qr_phishing": [
        "Preview a QR code's URL before opening it — many phone scanners show the target first.",
    ],
    "spam": [
        "Report and delete unsolicited marketing; do not unsubscribe from unknown senders.",
    ],
    "safe": [
        "Even safe messages benefit from good hygiene: verify links before entering credentials.",
    ],
}


class EducationalContentService:
    def enrich(self, *, verdict: str, base_tips: list[str]) -> list[str]:
        tips: list[str] = list(base_tips or [])
        for guidance in _GUIDANCE.get(verdict, []):
            if guidance not in tips:
                tips.append(guidance)
        return tips[:6]
