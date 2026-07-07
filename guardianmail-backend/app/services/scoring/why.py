"""Builds the "Why we told you this" explanation block returned to the UI.

The frontend renders this after every scan (email, link, QR). It maps each
raw signal into user-facing language plus the device-impact reasoning.
"""
from __future__ import annotations

from typing import Any

CATEGORY_TITLES = {
    "url_intel":    "Link reputation",
    "ocr":          "Content in images/PDF",
    "email_auth":   "Sender authentication",
    "attachment":   "File attachments",
    "device_trust": "Origin device",
    "community":    "Community reports",
}

DEVICE_IMPACT = {
    "url_intel":    "Visiting the link could install spyware, steal saved passwords, or hijack browser sessions.",
    "ocr":          "Images with fake login prompts trick you into typing credentials that go straight to the attacker.",
    "email_auth":   "The message was not cryptographically signed by the domain it claims to come from — impersonation is likely.",
    "attachment":   "Opening the attachment can execute code with your user privileges — encrypt files (ransomware), read cookies, or exfiltrate documents.",
    "device_trust": "The scan came from a device we don't fully trust yet — treat any credentials entered on it as potentially exposed.",
    "community":    "Other MailGuard users already lost data to this exact artifact — the pattern is confirmed in the wild.",
}


def build(verdict: dict[str, Any], *, artifact_kind: str) -> dict[str, Any]:
    """verdict is the output of scoring.explainable.explain()."""
    signals = verdict.get("signals", [])
    by_cat: dict[str, list[dict]] = {}
    for s in signals:
        by_cat.setdefault(s["category"], []).append(s)

    reasons = []
    for cat, sigs in by_cat.items():
        reasons.append({
            "category": cat,
            "title": CATEGORY_TITLES.get(cat, cat),
            "device_impact": DEVICE_IMPACT.get(cat, ""),
            "signal_count": len(sigs),
            "top_severity": max((s["severity"] for s in sigs),
                                key=lambda x: ["info", "low", "medium", "high", "critical"].index(x)
                                if x in ["info", "low", "medium", "high", "critical"] else 0),
            "details": [s["detail"] for s in sigs],
            "weight_contribution": sum(s["weight"] for s in sigs),
        })
    reasons.sort(key=lambda r: r["weight_contribution"], reverse=True)

    return {
        "artifact_kind": artifact_kind,        # "email" | "link" | "qr" | "social"
        "verdict": verdict.get("verdict"),
        "risk_score": verdict.get("risk_score"),
        "confidence": verdict.get("confidence"),
        "headline": _headline(verdict.get("verdict"), verdict.get("risk_score", 0)),
        "reasons": reasons,
        "next_steps": _next_steps(verdict.get("verdict")),
    }


def _headline(verdict: str | None, score: int) -> str:
    if verdict == "phishing":
        return f"High-risk phishing indicators ({score}/100). Do not interact."
    if verdict == "suspicious":
        return f"Suspicious activity detected ({score}/100). Verify before trusting."
    return f"No high-risk signals detected ({score}/100)."


def _next_steps(verdict: str | None) -> list[str]:
    if verdict in ("phishing", "fraud"):
        return [
            "Do not click links or download attachments.",
            "Report the sender to your IT / email provider.",
            "If you already interacted, change passwords used on that device and enable MFA.",
        ]
    if verdict == "suspicious":
        return [
            "Verify the sender through a trusted channel (phone, official website).",
            "Hover over links before clicking to inspect the real destination.",
            "Do not enter credentials on pages opened from this message.",
        ]
    return ["No action required. Keep MailGuard running for continuous protection."]
