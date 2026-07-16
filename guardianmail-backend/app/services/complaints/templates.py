"""Backend-managed complaint templates.

Templates are stored per-category and expanded with scan data. They can be
overridden per-deployment via the `complaint_templates` collection without
touching code — see `get_template()`.
"""
from __future__ import annotations

from string import Template
from typing import Any

from app.database.mongodb import get_db


# Default templates keyed by (destination, category). `destination` is one of:
#   cybercrime_gov_in  →  https://cybercrime.gov.in
#   report_phishing    →  report@phishing.gov.in
DEFAULT_TEMPLATES: dict[str, dict[str, dict[str, str]]] = {
    "cybercrime_gov_in": {
        "phishing": {
            "subject": "Phishing attempt against $victim_email — GuardianMail evidence pack $evidence_id",
            "body": (
                "To,\nThe Investigating Officer,\nNational Cyber Crime Reporting Portal\n\n"
                "Sir/Madam,\n\n"
                "I, $victim_name (email: $victim_email), wish to report a phishing "
                "attempt received on $received_at. The message was sent from "
                "'$sender' with subject '$subject'.\n\n"
                "Threat classification: $verdict (risk score $risk_score/100, "
                "confidence $confidence%).\n"
                "Attack category: $attack_category\n\n"
                "== Indicators ==\n$indicators\n\n"
                "== Malicious URLs / Domains ==\n$urls\n\n"
                "== Evidence pack ==\nHash: $evidence_hash\nBundle: $evidence_id\n\n"
                "I request appropriate action under the Information Technology Act, 2000.\n\n"
                "Yours faithfully,\n$victim_name\n$victim_phone\n"
            ),
        },
        "fraud": {
            "subject": "Financial fraud attempt — GuardianMail evidence pack $evidence_id",
            "body": (
                "To,\nThe Investigating Officer,\nNational Cyber Crime Reporting Portal\n\n"
                "I wish to report a financial fraud / bank-impersonation attempt "
                "targeting my account, received on $received_at from '$sender'.\n\n"
                "Subject: $subject\nVerdict: $verdict (risk $risk_score/100)\n\n"
                "== Fraud indicators ==\n$indicators\n\n"
                "== Malicious infrastructure ==\n$urls\n\n"
                "Evidence pack hash: $evidence_hash (bundle $evidence_id).\n\n"
                "Kindly initiate an investigation and block the offending "
                "infrastructure at the earliest.\n\n$victim_name\n$victim_phone\n"
            ),
        },
        "suspicious": {
            "subject": "Suspicious communication report — $evidence_id",
            "body": (
                "I am reporting a suspicious message flagged by GuardianMail on "
                "$received_at. Details below for record and review.\n\n"
                "Sender: $sender\nSubject: $subject\nVerdict: $verdict\n"
                "Risk score: $risk_score/100\n\n"
                "Indicators:\n$indicators\n\nURLs:\n$urls\n\n"
                "Evidence bundle: $evidence_id (SHA-256 $evidence_hash).\n\n"
                "$victim_name\n"
            ),
        },
    },
    "report_phishing": {
        "phishing": {
            "subject": "Phishing report — $sender — $evidence_id",
            "body": (
                "Reporting a confirmed phishing message.\n\n"
                "Received-At: $received_at\nSender: $sender\nSubject: $subject\n"
                "Message-ID: $message_id\nVerdict: $verdict (risk $risk_score)\n\n"
                "URLs:\n$urls\n\nIndicators:\n$indicators\n\n"
                "Full headers, indicators and raw artefacts are attached in the "
                "GuardianMail evidence pack ($evidence_id, sha256=$evidence_hash).\n\n"
                "— Submitted via GuardianMail on behalf of $victim_email\n"
            ),
        },
        "fraud": {
            "subject": "Financial fraud report — $sender — $evidence_id",
            "body": (
                "Reporting a financial fraud attempt.\n\n"
                "Received-At: $received_at\nSender: $sender\nSubject: $subject\n"
                "Verdict: $verdict (risk $risk_score)\n\n"
                "Malicious URLs / domains:\n$urls\n\nIndicators:\n$indicators\n\n"
                "Evidence pack: $evidence_id (sha256=$evidence_hash)\n\n"
                "— GuardianMail on behalf of $victim_email\n"
            ),
        },
        "suspicious": {
            "subject": "Suspicious message report — $evidence_id",
            "body": (
                "Suspicious message flagged by GuardianMail.\n\n"
                "Sender: $sender\nSubject: $subject\nVerdict: $verdict "
                "(risk $risk_score)\n\nIndicators:\n$indicators\n\nURLs:\n$urls\n\n"
                "Evidence pack $evidence_id.\n\n— $victim_email\n"
            ),
        },
    },
}


async def get_template(destination: str, category: str) -> dict[str, str]:
    db = get_db()
    doc = await db.complaint_templates.find_one({
        "destination": destination, "category": category,
    })
    if doc:
        return {"subject": doc["subject"], "body": doc["body"]}
    tpl = DEFAULT_TEMPLATES.get(destination, {}).get(category) or \
          DEFAULT_TEMPLATES.get(destination, {}).get("suspicious")
    if not tpl:
        raise ValueError(f"no template for {destination}/{category}")
    return tpl


def _bullet(items: list[str]) -> str:
    return "\n".join(f"  • {i}" for i in items) if items else "  (none observed)"


async def render(destination: str, category: str, ctx: dict[str, Any]) -> dict[str, str]:
    tpl = await get_template(destination, category)
    filled = {
        "victim_name": ctx.get("victim_name") or "GuardianMail user",
        "victim_email": ctx.get("victim_email") or "unknown",
        "victim_phone": ctx.get("victim_phone") or "N/A",
        "sender": ctx.get("sender") or "unknown",
        "subject": ctx.get("subject") or "(no subject)",
        "message_id": ctx.get("message_id") or "N/A",
        "received_at": ctx.get("received_at") or "unknown",
        "verdict": ctx.get("verdict") or "suspicious",
        "risk_score": ctx.get("risk_score", 0),
        "confidence": ctx.get("confidence", 0),
        "attack_category": ctx.get("attack_category") or "unclassified",
        "indicators": _bullet(ctx.get("indicators") or []),
        "urls": _bullet(ctx.get("urls") or []),
        "evidence_id": ctx.get("evidence_id") or "N/A",
        "evidence_hash": ctx.get("evidence_hash") or "N/A",
    }
    return {
        "subject": Template(tpl["subject"]).safe_substitute(filled),
        "body": Template(tpl["body"]).safe_substitute(filled),
    }
