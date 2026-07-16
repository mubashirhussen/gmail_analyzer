"""Threat Intelligence Engine — orchestrator.

`ThreatEngineService` glues together:
    email/artefact extraction → provider fan-out → analysis services →
    scoring → report finalization.

It is transport-agnostic: the API layer, Celery tasks, and future
webhook handlers all call `scan_email` / `scan_url`.
"""
from __future__ import annotations

from typing import Iterable

from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.threat import ThreatReport
from app.repositories.emails import EmailsRepository
from app.repositories.threats import ThreatReportRepository
from app.services.threat.attachment_analysis_service import (
    attachment_analysis_service,
)
from app.services.threat.authentication_analysis_service import (
    authentication_analysis_service,
)
from app.services.threat.domain_analysis_service import domain_analysis_service
from app.services.threat.header_analysis_service import header_analysis_service
from app.services.threat.ip_reputation_service import ip_reputation_service
from app.services.threat.normalizer import (
    domain_of_email,
    extract_urls,
    normalize_url,
    registered_domain,
)
from app.services.threat.provider_aggregation_service import (
    provider_aggregation_service,
)
from app.services.threat.report_service import threat_report_service
from app.services.threat.score_service import threat_score_service
from app.services.threat.url_analysis_service import url_analysis_service

log = get_logger(__name__)


class ThreatEngineService:
    async def scan_email(
        self,
        *,
        user_id: str,
        email_id: str,
        triggered_by: str = "auto_sync",
        force: bool = False,
    ) -> ThreatReport:
        db = get_db()
        email_repo = EmailsRepository(db)
        email = await email_repo.find_by_id(email_id)
        if not email:
            raise ValueError(f"email {email_id} not found")

        report = await threat_report_service.create_pending(
            user_id=user_id,
            email_id=email_id,
            channel="email",
            triggered_by=triggered_by,
        )
        try:
            artefacts = self._artefacts_for_email(email)
            outcomes = await provider_aggregation_service.scan_artefacts(
                artefacts,
                threat_report_id=report.id,
                user_id=user_id,
                force=force,
            )
            headers = self._headers_as_pairs(email)
            attachments = self._attachments_as_dicts(email)
            urls = self._urls_from_email(email)
            domains = sorted({registered_domain(u) or "" for u in urls if registered_domain(u)})

            url_ind = url_analysis_service.analyze(urls, outcomes)
            dom_ind = domain_analysis_service.analyze(domains, outcomes)
            hdr_ind = header_analysis_service.analyze(
                headers,
                sent_at=getattr(email, "received_at", None) or getattr(email, "created_at", None),
            )
            auth_results, auth_ind = authentication_analysis_service.analyze(headers)
            att_ind = attachment_analysis_service.analyze(attachments)
            origin_ip = header_analysis_service.extract_origin_ip(headers)
            ip_ind = ip_reputation_service.analyze(origin_ip, outcomes)

            all_ind = [*url_ind, *dom_ind, *hdr_ind, *auth_ind, *att_ind, *ip_ind]
            scoring = threat_score_service.compute(
                all_ind,
                providers_ok=sum(1 for o in outcomes if o.status == "ok"),
                providers_total=len(outcomes),
            )
            return await threat_report_service.finalize(
                report,
                outcomes=outcomes,
                indicators=all_ind,
                scoring=scoring,
                urls=len(urls),
                domains=len(domains),
                attachments=len(attachments),
            )
        except Exception as e:
            log.exception("threat_scan_failed", email_id=email_id)
            await threat_report_service.mark_failed(report, reason=str(e)[:200])
            raise

    async def scan_url(
        self, *, user_id: str, url: str, triggered_by: str = "user_action",
        force: bool = False,
    ) -> ThreatReport:
        canonical = normalize_url(url) or url
        report = await threat_report_service.create_pending(
            user_id=user_id, email_id=None,
            channel="url", triggered_by=triggered_by,
        )
        try:
            reg = registered_domain(canonical)
            artefacts: list[tuple[str, str]] = [("url", canonical)]
            if reg:
                artefacts.append(("domain", reg))
            outcomes = await provider_aggregation_service.scan_artefacts(
                artefacts, threat_report_id=report.id, user_id=user_id, force=force,
            )
            url_ind = url_analysis_service.analyze([canonical], outcomes)
            dom_ind = domain_analysis_service.analyze([reg] if reg else [], outcomes)
            all_ind = [*url_ind, *dom_ind]
            scoring = threat_score_service.compute(
                all_ind,
                providers_ok=sum(1 for o in outcomes if o.status == "ok"),
                providers_total=len(outcomes),
            )
            return await threat_report_service.finalize(
                report,
                outcomes=outcomes,
                indicators=all_ind,
                scoring=scoring,
                urls=1, domains=1 if reg else 0, attachments=0,
            )
        except Exception as e:
            log.exception("threat_url_scan_failed", url=canonical)
            await threat_report_service.mark_failed(report, reason=str(e)[:200])
            raise

    async def recheck(self, *, user_id: str, report_id: str) -> ThreatReport:
        db = get_db()
        base = await ThreatReportRepository(db).find_by_id(report_id)
        if not base or base.user_id != user_id:
            raise ValueError("report not found")
        if base.email_id:
            return await self.scan_email(
                user_id=user_id, email_id=base.email_id,
                triggered_by="recheck", force=True,
            )
        raise ValueError("URL-scan rechecks require the original URL — not stored")

    # ---- artefact extraction ------------------------------------------
    def _headers_as_pairs(self, email) -> list[dict]:
        """Convert `EmailDoc.headers` (structured `ParsedHeaders`) into the
        `[{name, value}]` shape the header/auth analysers consume.
        """
        h = getattr(email, "headers", None)
        if h is None:
            return []
        if isinstance(h, list):
            return h  # already pairs (forwarded scans)
        out: list[dict] = []
        mapping = {
            "message_id": "Message-ID",
            "return_path": "Return-Path",
            "reply_to": "Reply-To",
            "authentication_results": "Authentication-Results",
            "x_originating_ip": "X-Originating-IP",
            "user_agent": "User-Agent",
            "mailer": "X-Mailer",
            "content_type": "Content-Type",
            "list_unsubscribe": "List-Unsubscribe",
        }
        for attr, name in mapping.items():
            v = getattr(h, attr, None)
            if v:
                out.append({"name": name, "value": str(v)})
        for rcv in (getattr(h, "received", None) or []):
            out.append({"name": "Received", "value": str(rcv)})
        from_hdr = getattr(email, "sender", "") or ""
        if from_hdr:
            out.append({"name": "From", "value": from_hdr})
        return out

    def _urls_from_email(self, email) -> list[str]:
        urls: list[str] = []
        for u in getattr(email, "urls", None) or []:
            n = getattr(u, "normalized", None) or getattr(u, "raw", None) or (
                u.get("normalized") if isinstance(u, dict) else None
            )
            if n:
                urls.append(n)
        body = getattr(email, "body_text", None) or getattr(email, "snippet", "") or ""
        html = getattr(email, "body_html", None) or ""
        urls.extend(extract_urls(f"{body}\n{html}", limit=100))
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            n = normalize_url(u)
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out[:50]

    def _attachments_as_dicts(self, email) -> list[dict]:
        raw = getattr(email, "attachments", None) or []
        out: list[dict] = []
        for a in raw:
            if isinstance(a, dict):
                out.append({
                    "filename": a.get("filename"),
                    "mime_type": a.get("mime") or a.get("mime_type"),
                    "size": a.get("size") or 0,
                    "sha256": a.get("sha256"),
                    "encrypted": bool(a.get("encrypted", False)),
                })
                continue
            out.append({
                "filename": getattr(a, "filename", None),
                "mime_type": getattr(a, "mime", None),
                "size": getattr(a, "size", 0),
                "sha256": getattr(a, "sha256", None),
                "encrypted": bool(getattr(a, "encrypted", False)),
            })
        return out

    def _artefacts_for_email(self, email) -> Iterable[tuple[str, str]]:
        urls = self._urls_from_email(email)
        domains: set[str] = set()
        for u in urls:
            d = registered_domain(u)
            if d:
                domains.add(d)
        sender = getattr(email, "sender_email", "") or getattr(email, "sender", "") or ""
        sdom = domain_of_email(sender)
        if sdom:
            domains.add(sdom)
        headers = self._headers_as_pairs(email)
        origin_ip = header_analysis_service.extract_origin_ip(headers)
        artefacts: list[tuple[str, str]] = []
        for u in urls:
            artefacts.append(("url", u))
        for d in domains:
            artefacts.append(("domain", d))
        if origin_ip:
            artefacts.append(("ip", origin_ip))
        for att in self._attachments_as_dicts(email):
            sha = (att.get("sha256") or "").strip().lower()
            if sha and len(sha) == 64:
                artefacts.append(("file_hash", sha))
        return artefacts


threat_engine_service = ThreatEngineService()
