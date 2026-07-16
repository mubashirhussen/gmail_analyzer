"""Educational Engine — concise, curated explanations of security topics.

Content is authored in-repo (not model-generated) so lookups are safe,
deterministic, and always available even when no LLM provider is
configured. The copilot may cite these entries in `related_concepts`.
"""
from __future__ import annotations

_LIBRARY: dict[str, str] = {
    "phishing": "Phishing tricks users into revealing credentials or clicking malicious links via impersonation.",
    "malware": "Malicious software designed to harm, exfiltrate data, or take control of a device.",
    "bec": "Business Email Compromise: attackers impersonate executives or vendors to authorize fraudulent transfers.",
    "invoice_fraud": "Fake invoices from spoofed or hijacked vendor accounts requesting payment to attacker-controlled accounts.",
    "credential_theft": "Attempts to capture usernames/passwords via fake login pages or forms.",
    "qr_phishing": "Quishing: QR codes redirect victims to phishing pages, often bypassing email URL scanners.",
    "safe_browsing": "Verify URLs, prefer bookmarks, check HTTPS + domain, and avoid clicking links in unexpected emails.",
    "password_safety": "Use a password manager, enable MFA, never reuse passwords across accounts.",
    "spf": "Sender Policy Framework: DNS record listing IPs allowed to send mail for a domain.",
    "dkim": "DomainKeys Identified Mail: cryptographic signature proving the email was not modified in transit.",
    "dmarc": "DMARC ties SPF/DKIM to the visible From: domain and tells receivers what to do on failure.",
    "urgency": "Attackers manufacture urgency to bypass rational verification — pause and verify out-of-band.",
    "typosquatting": "Look-alike domains (e.g. rn vs m) trick users into trusting attacker-controlled sites.",
    "homograph": "Unicode look-alike characters used to spoof legitimate domains.",
}


class EducationalService:
    def lookup(self, topic: str) -> str | None:
        return _LIBRARY.get(topic.strip().lower().replace(" ", "_"))

    def bulk(self, topics: list[str]) -> dict[str, str]:
        return {t: self.lookup(t) or "" for t in topics}

    def topics(self) -> list[str]:
        return sorted(_LIBRARY.keys())


educational_service = EducationalService()
