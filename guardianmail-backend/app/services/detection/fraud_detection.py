"""FraudDetectionService — BEC, invoice, payroll, wire-transfer, vendor fraud.

Deterministic pattern set. Findings are persisted to `fraud_indicators`
and echoed into the correlated detection result.
"""
from __future__ import annotations

import re
from typing import Any

from app.database.mongodb import get_db
from app.models.detection import FraudIndicator
from app.repositories.detection import FraudIndicatorRepository


_WIRE_PATTERNS = re.compile(
    r"\b(wire\s+transfer|swift\s+code|iban|routing\s+number|remit\s+to|"
    r"beneficiary\s+bank)\b", re.I,
)
_INVOICE_PATTERNS = re.compile(
    r"\b(invoice\s*#?\d+|updated\s+invoice|revised\s+invoice|"
    r"attached\s+invoice|purchase\s+order|po\s*#\d+)\b", re.I,
)
_PAYROLL_PATTERNS = re.compile(
    r"\b(direct\s+deposit|change\s+.{0,10}bank\s+account|update\s+.{0,10}payroll|"
    r"new\s+account\s+details)\b", re.I,
)
_BANK_CHANGE = re.compile(
    r"\b(new\s+bank\s+details|change\s+.{0,10}beneficiary|update\s+.{0,15}account)\b",
    re.I,
)
_VENDOR = re.compile(
    r"\b(vendor|supplier|contractor)\b.*\b(new\s+account|update\s+details)\b",
    re.I | re.S,
)
_CEO_HINT = re.compile(
    r"\b(ceo|cfo|coo|president|director|chairman)\b", re.I,
)
_GIFT_CARD = re.compile(
    r"\b(gift\s+card|prepaid\s+card|itunes\s+card|amazon\s+card)\b", re.I,
)


class FraudDetectionService:
    def scan(
        self, *, subject: str | None, body: str | None, sender: str | None,
    ) -> list[dict[str, Any]]:
        text = f"{subject or ''}\n{body or ''}"
        findings: list[dict[str, Any]] = []

        def _add(kind: str, severity: str, match: str, weight: float,
                 evidence: dict | None = None):
            findings.append({
                "kind": kind, "severity": severity, "weight": weight,
                "value": match[:120], "evidence": evidence or {},
            })

        m = _WIRE_PATTERNS.search(text)
        if m:
            _add("wire_transfer", "high", m.group(0), 25)

        m = _INVOICE_PATTERNS.search(text)
        if m:
            _add("invoice_fraud", "high", m.group(0), 22)

        m = _PAYROLL_PATTERNS.search(text)
        if m:
            _add("payroll_fraud", "high", m.group(0), 25)

        m = _BANK_CHANGE.search(text)
        if m:
            _add("banking_change", "high", m.group(0), 20)

        m = _VENDOR.search(text)
        if m:
            _add("vendor_fraud", "medium", m.group(0)[:80], 18)

        m = _GIFT_CARD.search(text)
        if m:
            _add("gift_card_fraud", "high", m.group(0), 25)

        # BEC / CEO fraud: executive hint + urgency + financial ask.
        if _CEO_HINT.search(text) and (_WIRE_PATTERNS.search(text)
                                        or _GIFT_CARD.search(text)
                                        or "urgent" in text.lower()):
            _add("bec_ceo_fraud", "critical",
                 "executive_urgent_financial", 35,
                 evidence={"sender": sender or ""})

        return findings

    async def persist(
        self, *, user_id: str, detection_id: str, email_id: str | None,
        findings: list[dict[str, Any]],
    ) -> None:
        if not findings:
            return
        db = get_db()
        repo = FraudIndicatorRepository(db)
        docs = [
            FraudIndicator(
                user_id=user_id, detection_id=detection_id, email_id=email_id,
                kind=f["kind"], severity=f.get("severity", "medium"),
                value=f.get("value"), evidence=f.get("evidence") or {},
            ).to_mongo()
            for f in findings
        ]
        try:
            await repo.collection.insert_many(docs, ordered=False)
        except Exception:
            # Non-fatal — persistence is additive audit data.
            pass


fraud_detection_service = FraudDetectionService()
