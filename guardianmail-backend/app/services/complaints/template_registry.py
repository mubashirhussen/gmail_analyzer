"""Backend-managed complaint template registry (Module 9).

Additive to `templates.py`. Defines the enterprise template catalogue
covering every complaint type mandated by the module spec:

    phishing, credential_theft, bec, invoice_fraud, identity_theft,
    malware, fake_login, payment_scam, lottery_scam, investment_scam,
    crypto_scam, social_engineering, unknown

crossed with every destination:

    cybercrime_gov_in, cert_in, org_security_team, corporate_soc,
    internal_security, custom

Every template supports:
  * Dynamic variables (Jinja2 syntax so blocks/loops work),
  * Localization via `locale` key (default "en"),
  * Future versioning via `version` — templates are addressable as
    (destination, category, locale, version). DB overrides in the
    `complaint_templates` collection win over the defaults below.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jinja2 import Environment, StrictUndefined, TemplateError, select_autoescape

from app.database.mongodb import get_db


# --------------------------------------------------------------------------- #
# Canonical enums                                                             #
# --------------------------------------------------------------------------- #
COMPLAINT_CATEGORIES: tuple[str, ...] = (
    "phishing", "credential_theft", "bec", "invoice_fraud",
    "identity_theft", "malware", "fake_login", "payment_scam",
    "lottery_scam", "investment_scam", "crypto_scam",
    "social_engineering", "unknown",
)

COMPLAINT_DESTINATIONS: tuple[str, ...] = (
    "cybercrime_gov_in", "cert_in", "org_security_team",
    "corporate_soc", "internal_security", "custom",
)

DEFAULT_LOCALE = "en"
DEFAULT_VERSION = 1


# --------------------------------------------------------------------------- #
# Rendering environment                                                       #
# --------------------------------------------------------------------------- #
_env = Environment(
    autoescape=select_autoescape(default=False),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    enable_async=False,
)


@dataclass(frozen=True)
class ComplaintTemplate:
    destination: str
    category: str
    subject: str
    body: str
    locale: str = DEFAULT_LOCALE
    version: int = DEFAULT_VERSION
    tags: tuple[str, ...] = field(default_factory=tuple)

    def render(self, ctx: dict[str, Any]) -> dict[str, str]:
        try:
            subject = _env.from_string(self.subject).render(**ctx)
            body = _env.from_string(self.body).render(**ctx)
        except TemplateError as exc:  # pragma: no cover - templating bugs
            raise ValueError(f"template render failed: {exc}") from exc
        return {"subject": subject.strip(), "body": body.strip()}


# --------------------------------------------------------------------------- #
# Reusable blocks                                                             #
# --------------------------------------------------------------------------- #
_HEADER_BLOCK = (
    "Received-At: {{ received_at }}\n"
    "Sender: {{ sender }}\n"
    "Subject: {{ subject_line }}\n"
    "Message-ID: {{ message_id or 'N/A' }}\n"
    "SPF: {{ spf or 'unknown' }} | DKIM: {{ dkim or 'unknown' }} | "
    "DMARC: {{ dmarc or 'unknown' }}\n"
)

_EVIDENCE_BLOCK = (
    "Evidence Pack ID : {{ evidence_id }}\n"
    "SHA-256          : {{ evidence_hash }}\n"
    "Generated-At     : {{ evidence_generated_at }}\n"
    "Chain-of-Custody : {{ chain_of_custody_id }}\n"
)

_INDICATOR_BLOCK = (
    "{% if indicators %}"
    "{% for i in indicators %}  - {{ i }}\n{% endfor %}"
    "{% else %}  (no explicit indicators recorded)\n{% endif %}"
)

_URL_BLOCK = (
    "{% if urls %}"
    "{% for u in urls %}  - {{ u }}\n{% endfor %}"
    "{% else %}  (no suspicious URLs recorded)\n{% endif %}"
)


def _std_signoff() -> str:
    return (
        "Respectfully submitted,\n"
        "{{ victim_name or victim_email }}\n"
        "{% if victim_phone %}Contact: {{ victim_phone }}\n{% endif %}"
    )


def _std_body(intro: str, extra: str = "") -> str:
    return (
        f"{intro}\n\n"
        "== Incident Summary ==\n"
        "Category      : {{ category_label }}\n"
        "Verdict       : {{ verdict }} (risk {{ risk_score }}/100, "
        "confidence {{ confidence }}%)\n"
        "Attack Vector : {{ attack_category or 'unclassified' }}\n\n"
        "== Message Metadata ==\n"
        f"{_HEADER_BLOCK}\n"
        "== Threat Indicators ==\n"
        f"{_INDICATOR_BLOCK}\n"
        "== Suspicious URLs / Domains ==\n"
        f"{_URL_BLOCK}\n"
        "== AI Analysis Summary ==\n"
        "{{ ai_summary or '(no AI summary available)' }}\n\n"
        "== Recommended Action ==\n"
        "{{ recommended_action or 'Investigate and block offending infrastructure.' }}\n\n"
        "== Evidence Attached ==\n"
        f"{_EVIDENCE_BLOCK}\n"
        f"{extra}"
        f"{_std_signoff()}"
    )


# --------------------------------------------------------------------------- #
# Default catalogue                                                           #
# --------------------------------------------------------------------------- #
_CATEGORY_LABEL = {
    "phishing": "Phishing",
    "credential_theft": "Credential Theft",
    "bec": "Business Email Compromise (BEC)",
    "invoice_fraud": "Invoice / Vendor Fraud",
    "identity_theft": "Identity Theft",
    "malware": "Malware Delivery",
    "fake_login": "Fake Login Page",
    "payment_scam": "Payment Scam",
    "lottery_scam": "Lottery / Prize Scam",
    "investment_scam": "Investment Scam",
    "crypto_scam": "Cryptocurrency Scam",
    "social_engineering": "Social Engineering",
    "unknown": "Unclassified Threat",
}


def _intro_for(destination: str, category: str) -> str:
    label = _CATEGORY_LABEL[category]
    if destination == "cybercrime_gov_in":
        return (
            "To,\nThe Investigating Officer,\n"
            "National Cyber Crime Reporting Portal\n\n"
            f"Sir/Madam,\n\nI, {{{{ victim_name or victim_email }}}}, wish to "
            f"formally report a {label.lower()} incident received on "
            "{{ received_at }}. The complete forensic evidence pack prepared "
            "by GuardianMail is described below."
        )
    if destination == "cert_in":
        return (
            "To,\nThe Incident Response Team,\n"
            "Indian Computer Emergency Response Team (CERT-In)\n\n"
            f"Subject: {label} incident report — evidence bundle "
            "{{ evidence_id }}\n\n"
            "This report is filed under CERT-In's cyber-incident "
            "reporting guidelines."
        )
    if destination == "org_security_team":
        return (
            f"Team,\n\nThe organization security team is being notified of a "
            f"confirmed {label.lower()} attempt against "
            "{{ victim_email }}."
        )
    if destination == "corporate_soc":
        return (
            f"SOC Analysts,\n\nOpening a ticket for a {label.lower()} "
            "incident. Full evidence bundle attached."
        )
    if destination == "internal_security":
        return (
            f"Internal Security,\n\nFor immediate triage — {label.lower()} "
            "targeting {{ victim_email }}."
        )
    # custom / fallback
    return (
        f"Recipient,\n\nA {label.lower()} incident has been documented by "
        "GuardianMail. Details follow for your review."
    )


def _build_default_catalogue() -> dict[tuple[str, str, str, int], ComplaintTemplate]:
    out: dict[tuple[str, str, str, int], ComplaintTemplate] = {}
    for dest in COMPLAINT_DESTINATIONS:
        for cat in COMPLAINT_CATEGORIES:
            intro = _intro_for(dest, cat)
            subject = (
                "[GuardianMail] "
                f"{_CATEGORY_LABEL[cat]} incident — "
                "{{ sender }} — pack {{ evidence_id }}"
            )
            body = _std_body(intro)
            tpl = ComplaintTemplate(
                destination=dest, category=cat,
                subject=subject, body=body,
                locale=DEFAULT_LOCALE, version=DEFAULT_VERSION,
                tags=(cat, dest),
            )
            out[(dest, cat, DEFAULT_LOCALE, DEFAULT_VERSION)] = tpl
    return out


_DEFAULT_CATALOGUE = _build_default_catalogue()


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #
async def get_template(
    destination: str, category: str,
    *, locale: str = DEFAULT_LOCALE, version: int | None = None,
) -> ComplaintTemplate:
    """Fetch a template — DB override wins over the packaged default."""
    if destination not in COMPLAINT_DESTINATIONS:
        raise ValueError(f"unknown destination {destination}")
    if category not in COMPLAINT_CATEGORIES:
        category = "unknown"
    db = get_db()
    query: dict[str, Any] = {
        "destination": destination, "category": category, "locale": locale,
    }
    if version is not None:
        query["version"] = version
    doc = await db.complaint_templates.find_one(
        query, sort=[("version", -1)],
    )
    if doc:
        return ComplaintTemplate(
            destination=doc["destination"],
            category=doc["category"],
            subject=doc["subject"],
            body=doc["body"],
            locale=doc.get("locale", DEFAULT_LOCALE),
            version=int(doc.get("version", DEFAULT_VERSION)),
            tags=tuple(doc.get("tags", ())),
        )
    key_version = version or DEFAULT_VERSION
    key = (destination, category, locale, key_version)
    if key in _DEFAULT_CATALOGUE:
        return _DEFAULT_CATALOGUE[key]
    return _DEFAULT_CATALOGUE[(destination, category, DEFAULT_LOCALE, DEFAULT_VERSION)]


def category_label(category: str) -> str:
    return _CATEGORY_LABEL.get(category, _CATEGORY_LABEL["unknown"])


async def list_templates() -> list[dict[str, Any]]:
    """List the catalogue (defaults + DB overrides)."""
    catalogue: dict[tuple[str, str, str], dict[str, Any]] = {}
    for (dest, cat, locale, version), tpl in _DEFAULT_CATALOGUE.items():
        catalogue[(dest, cat, locale)] = {
            "destination": dest, "category": cat, "locale": locale,
            "version": version, "source": "default",
        }
    db = get_db()
    async for doc in db.complaint_templates.find({}):
        key = (doc["destination"], doc["category"], doc.get("locale", DEFAULT_LOCALE))
        catalogue[key] = {
            "destination": doc["destination"],
            "category": doc["category"],
            "locale": doc.get("locale", DEFAULT_LOCALE),
            "version": int(doc.get("version", DEFAULT_VERSION)),
            "source": "override",
        }
    return sorted(catalogue.values(), key=lambda x: (x["destination"], x["category"]))
