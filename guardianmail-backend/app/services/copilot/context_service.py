"""ContextService — assembles verified GuardianMail evidence for a scope.

The context is the *only* ground truth the LLM is allowed to reference. If
a section is missing, the service records that gap so the Response
Validator can flag unsupported claims.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.database.mongodb import get_db
from app.repositories.emails import EmailRepository
from app.repositories.ocr_reports import OCRReportRepository
from app.repositories.attachment_records import AttachmentRecordRepository
from app.repositories.evidence_packs import EvidencePackRepository
from app.repositories.provider_results import ProviderResultRepository
from app.repositories.threat_indicators import ThreatIndicatorRepository
from app.repositories.threats import ThreatReportRepository


@dataclass
class BuiltContext:
    scope: dict[str, Any]
    threat: dict[str, Any] | None = None
    email: dict[str, Any] | None = None
    headers: dict[str, Any] | None = None
    ocr: list[dict[str, Any]] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    providers: list[dict[str, Any]] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    evidence_pack: dict[str, Any] | None = None
    missing: list[str] = field(default_factory=list)

    @property
    def has_anchor(self) -> bool:
        return bool(self.threat or self.email or self.evidence_pack)

    def evidence_refs(self) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        if self.threat:
            refs.append({"source": "threat_report", "ref_id": self.threat.get("_id"),
                         "field": "risk_score", "value": self.threat.get("risk_score")})
        if self.email:
            refs.append({"source": "email", "ref_id": self.email.get("_id"),
                         "field": "subject", "value": self.email.get("subject")})
        for p in self.providers[:8]:
            refs.append({"source": f"provider:{p.get('provider')}", "ref_id": p.get("_id"),
                         "field": "verdict", "value": p.get("verdict")})
        for i in self.indicators[:12]:
            refs.append({"source": "indicator", "ref_id": i.get("_id"),
                         "field": i.get("kind"), "value": i.get("value")})
        for a in self.attachments[:5]:
            refs.append({"source": "attachment", "ref_id": a.get("_id"),
                         "field": "filename", "value": a.get("filename")})
        for o in self.ocr[:3]:
            refs.append({"source": "ocr", "ref_id": o.get("_id"),
                         "field": "text_excerpt",
                         "value": (o.get("text") or "")[:160]})
        if self.evidence_pack:
            refs.append({"source": "evidence_pack",
                         "ref_id": self.evidence_pack.get("_id"),
                         "field": "sha256",
                         "value": self.evidence_pack.get("sha256")})
        return refs


class ContextService:
    """Builds a `BuiltContext` from verified GuardianMail data only."""

    async def build(
        self,
        *,
        user_id: str,
        scope: dict[str, Any],
    ) -> BuiltContext:
        db = get_db()
        ctx = BuiltContext(scope=scope)

        threats = ThreatReportRepository(db)
        emails = EmailRepository(db)
        providers = ProviderResultRepository(db)
        indicators = ThreatIndicatorRepository(db)
        ocr_repo = OCRReportRepository(db)
        attach_repo = AttachmentRecordRepository(db)
        packs = EvidencePackRepository(db)

        threat_doc = None
        threat_id = scope.get("threat_id")
        email_id = scope.get("email_id")

        if threat_id:
            t = await threats.find_by_id(threat_id)
            if t and t.get("user_id") == user_id:
                threat_doc = t
        if not threat_doc and email_id:
            t = await threats.find_one(
                {"email_id": email_id, "user_id": user_id}, sort=[("created_at", -1)]
            )
            if t:
                threat_doc = t
                threat_id = t.get("_id")

        if threat_doc:
            ctx.threat = threat_doc
        else:
            ctx.missing.append("threat_report")

        if not email_id and threat_doc:
            email_id = threat_doc.get("email_id")

        if email_id:
            e = await emails.find_by_id(email_id)
            if e and e.get("user_id") == user_id:
                ctx.email = e
                ctx.headers = e.get("headers") or {}
            else:
                ctx.missing.append("email")

        if threat_id:
            try:
                prov_docs = await providers.collection.find(
                    {"threat_id": threat_id}
                ).to_list(length=25)
                ctx.providers = prov_docs
            except Exception:
                ctx.missing.append("providers")

            try:
                ind_docs = await indicators.collection.find(
                    {"threat_id": threat_id}
                ).to_list(length=50)
                ctx.indicators = ind_docs
            except Exception:
                ctx.missing.append("indicators")

        if email_id:
            try:
                att_docs = await attach_repo.collection.find(
                    {"email_id": email_id}
                ).to_list(length=25)
                ctx.attachments = att_docs
            except Exception:
                ctx.missing.append("attachments")

            try:
                ocr_docs = await ocr_repo.collection.find(
                    {"email_id": email_id}
                ).to_list(length=10)
                ctx.ocr = ocr_docs
            except Exception:
                ctx.missing.append("ocr")

        # Historical threats for this sender / user (last 5)
        try:
            sender = (ctx.email or {}).get("from_address")
            if sender:
                hist = await threats.collection.find(
                    {"user_id": user_id, "sender": sender}
                ).sort("created_at", -1).limit(5).to_list(length=5)
                ctx.history = [h for h in hist if h.get("_id") != threat_id]
        except Exception:
            pass

        if threat_id:
            try:
                pack = await packs.find_one({"threat_id": threat_id})
                if pack:
                    ctx.evidence_pack = pack
            except Exception:
                pass

        return ctx


context_service = ContextService()
