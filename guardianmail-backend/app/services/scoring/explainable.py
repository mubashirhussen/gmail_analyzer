"""Explainable risk scoring.

Combines individual signal categories into a final 0-100 risk score. Each
signal contributes independently, is capped, and is returned with the exact
reason it fired so the frontend can render "why we told you this".

Signal categories:
    - url_intel      : per-URL threat intelligence (GSB, VT, URLScan, RDAP, feeds)
    - ocr            : OCR-extracted text indicators (brand impersonation, urgency)
    - email_auth     : SPF / DKIM / DMARC results
    - attachment     : attachment mime + hash reputation
    - device_trust   : trust level of the device that produced the artifact
    - community      : how many MailGuard users reported the same artifact
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

URGENCY_RE = re.compile(
    r"\b(verify|urgent|immediately|suspended|unusual activity|password|"
    r"login|confirm your|act now|24 hours|final notice|last chance)\b",
    re.I,
)
BRAND_RE = re.compile(
    r"\b(paypal|amazon|microsoft|apple|google|netflix|bank of america|"
    r"chase|hdfc|sbi|icici|instagram|whatsapp|facebook|linkedin)\b",
    re.I,
)


@dataclass
class Signal:
    category: str      # url_intel | ocr | email_auth | attachment | device_trust | community
    weight: int        # 0-100 contribution to final score
    severity: str      # low | medium | high | critical | info
    detail: str        # human-readable "why this fired"
    evidence: dict[str, Any]  # raw provider output for auditing


def _clip(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(x)))


def score_url_intel(intel: dict) -> list[Signal]:
    out: list[Signal] = []
    for r in (intel or {}).get("results", []):
        providers = r.get("providers", [])
        flagged = [p for p in providers if p.get("status") == "flagged"]
        for p in flagged:
            name = p.get("provider", "url")
            weight = {"google_safe_browsing": 60, "virustotal": 50,
                      "urlscan": 35, "community phishing feeds": 55}.get(name.lower(), 30)
            out.append(Signal(
                category="url_intel", weight=weight, severity="high",
                detail=f"{name} flagged {r.get('url')}",
                evidence=p,
            ))
        # young domain
        rdap = next((p for p in providers if p.get("provider") == "rdap"), None)
        if rdap and rdap.get("registered_at"):
            from datetime import datetime, timezone
            try:
                reg = datetime.fromisoformat(rdap["registered_at"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - reg).days
                if age_days < 30:
                    out.append(Signal("url_intel", 25, "medium",
                                      f"Domain of {r.get('url')} registered only {age_days} days ago",
                                      {"age_days": age_days}))
            except Exception:
                pass
    return out


def score_ocr(ocr_results: list[dict]) -> list[Signal]:
    out: list[Signal] = []
    for o in ocr_results or []:
        text = o.get("text", "")
        if not text:
            continue
        urgency = URGENCY_RE.findall(text)
        brand = BRAND_RE.findall(text)
        if urgency:
            out.append(Signal("ocr", 15, "medium",
                              f"Attachment '{o.get('name')}' uses urgency language: {', '.join(set(urgency[:3]))}",
                              {"matches": list(set(urgency))[:8]}))
        if brand and urgency:
            out.append(Signal("ocr", 25, "high",
                              f"Attachment '{o.get('name')}' impersonates brand {list(set(brand))[0]} with urgency cues",
                              {"brand": list(set(brand)), "urgency": list(set(urgency))}))
    return out


def score_email_auth(auth: dict | None) -> list[Signal]:
    if not auth:
        return []
    out: list[Signal] = []
    for k in ("spf", "dkim", "dmarc"):
        v = auth.get(k)
        if v == "fail":
            out.append(Signal("email_auth", 20, "high",
                              f"{k.upper()} failed — sender identity cannot be verified",
                              {k: v}))
        elif v == "none":
            out.append(Signal("email_auth", 8, "low",
                              f"{k.upper()} not published for sender domain",
                              {k: v}))
    return out


def score_attachments(atts: list[dict]) -> list[Signal]:
    out: list[Signal] = []
    dangerous_mimes = {"application/x-msdownload", "application/x-msdos-program",
                       "application/x-sh", "application/x-executable"}
    for a in atts or []:
        mime = (a.get("mime") or "").lower()
        name = a.get("name", "")
        if mime in dangerous_mimes or name.lower().endswith((".exe", ".scr", ".bat", ".cmd", ".msi", ".js")):
            out.append(Signal("attachment", 45, "critical",
                              f"Attachment '{name}' has an executable type ({mime})",
                              {"mime": mime, "name": name}))
        elif name.lower().endswith((".zip", ".rar", ".7z")) and a.get("password_protected"):
            out.append(Signal("attachment", 30, "high",
                              f"Password-protected archive '{name}' hides its contents from scanners",
                              {"name": name}))
    return out


def score_device_trust(device: dict | None) -> list[Signal]:
    if not device:
        return []
    if device.get("trusted") is False:
        return [Signal("device_trust", 15, "medium",
                       f"Artifact originated from untrusted device '{device.get('label') or device.get('fingerprint')}'",
                       {"device_id": str(device.get("_id") or ""), "trusted": False})]
    return []


def score_community(report_count: int) -> list[Signal]:
    if report_count <= 0:
        return []
    if report_count >= 10:
        return [Signal("community", 40, "high",
                       f"{report_count} MailGuard users have independently reported this artifact",
                       {"report_count": report_count})]
    if report_count >= 3:
        return [Signal("community", 20, "medium",
                       f"{report_count} MailGuard users reported this artifact",
                       {"report_count": report_count})]
    return [Signal("community", 8, "low",
                   f"{report_count} MailGuard user reported this artifact",
                   {"report_count": report_count})]


def combine(signals: list[Signal]) -> dict[str, Any]:
    total = _clip(sum(s.weight for s in signals))
    if total >= 80:
        verdict = "phishing"
    elif total >= 55:
        verdict = "suspicious"
    elif total >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"
    # confidence rises with number of independent signal categories
    cats = {s.category for s in signals}
    confidence = _clip(30 + 15 * len(cats))
    return {
        "risk_score": total,
        "verdict": verdict,
        "confidence": confidence,
        "signals": [asdict(s) for s in signals],
        "contribution_breakdown": {
            c: sum(s.weight for s in signals if s.category == c) for c in cats
        },
    }


def explain(
    *,
    url_intel: dict | None = None,
    ocr_results: list[dict] | None = None,
    email_auth: dict | None = None,
    attachments: list[dict] | None = None,
    device: dict | None = None,
    community_report_count: int = 0,
) -> dict[str, Any]:
    """Run every signal scorer and return the combined explainable verdict."""
    signals: list[Signal] = []
    signals += score_url_intel(url_intel or {})
    signals += score_ocr(ocr_results or [])
    signals += score_email_auth(email_auth)
    signals += score_attachments(attachments or [])
    signals += score_device_trust(device)
    signals += score_community(community_report_count)
    return combine(signals)
