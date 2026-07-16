"""Threat report assembly + persistence."""
from __future__ import annotations

from collections import Counter
from typing import Iterable

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.threat import (
    IndicatorRollup,
    ProviderStatus,
    ScoreBundle,
    ThreatReport,
)
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_timeline import ThreatTimelineEvent
from app.repositories.threat_indicators import ThreatIndicatorRepository
from app.repositories.threat_timeline import ThreatTimelineRepository
from app.repositories.threats import ThreatReportRepository
from app.services.threat.normalizer import sha256_hex
from app.services.threat.providers.base import ProviderOutcome
from app.services.threat.score_service import ScoringResult

log = get_logger(__name__)


def _severity_to_ioc(sev: str) -> str:
    return {"info": "info", "low": "low", "medium": "medium",
            "high": "high", "critical": "critical"}.get(sev, "info")


def _indicator_kind_for(category: str) -> str:
    if category.startswith("url_") or category in {"insecure_transport",
                                                    "url_shortener",
                                                    "url_obfuscation",
                                                    "deep_subdomain_chain"}:
        return "url"
    if category.startswith("domain_") or category in {"whois_privacy",
                                                       "risky_tld",
                                                       "disposable_domain",
                                                       "idn_host",
                                                       "typosquat_domain",
                                                       "homograph_domain",
                                                       "ssl_expired",
                                                       "ssl_self_signed",
                                                       "ssl_invalid"}:
        return "domain"
    if category.startswith("ip_") or category == "private_origin_ip":
        return "ip"
    if category in {"executable_attachment", "double_extension",
                    "macro_office_document", "encrypted_archive",
                    "archive_attachment", "opaque_mime",
                    "known_malware_hash"}:
        return "file_hash"
    return "header"


class ThreatReportService:
    async def create_pending(
        self,
        *,
        user_id: str,
        email_id: str | None,
        channel: str,
        triggered_by: str,
        scan_generation: int = 1,
    ) -> ThreatReport:
        db = get_db()
        report = ThreatReport(
            user_id=user_id,
            email_id=email_id,
            channel=channel,  # type: ignore[arg-type]
            triggered_by=triggered_by,  # type: ignore[arg-type]
            scan_generation=scan_generation,
            scan_status="running",
            started_at=now_utc().isoformat(),
        )
        await ThreatReportRepository(db).insert(report)
        await self._timeline(report.id, user_id, "scan_started", "Scan started.")
        return report

    async def finalize(
        self,
        report: ThreatReport,
        *,
        outcomes: list[ProviderOutcome],
        indicators: Iterable,
        scoring: ScoringResult,
        urls: int,
        domains: int,
        attachments: int,
    ) -> ThreatReport:
        db = get_db()
        indicators_list = list(indicators)
        started_dt = None
        if report.started_at:
            try:
                from datetime import datetime
                started_dt = datetime.fromisoformat(report.started_at)
            except ValueError:
                started_dt = None
        completed = now_utc()
        duration_ms = int((completed - started_dt).total_seconds() * 1000) if started_dt else None

        provider_statuses = [
            ProviderStatus(
                provider=o.provider, status=o.status,
                latency_ms=o.latency_ms or None,
                error_code=o.error_code, error_message=o.error_message,
            )
            for o in outcomes
        ]
        ok = sum(1 for p in provider_statuses if p.status == "ok")

        # Rollup
        sev_counts: Counter[str] = Counter()
        kind_counts: Counter[str] = Counter()
        top: list[dict] = []
        for ind in indicators_list[:8]:
            top.append({
                "category": getattr(ind, "category", ""),
                "severity": getattr(ind, "severity", "info"),
                "detail": getattr(ind, "detail", ""),
            })
        for ind in indicators_list:
            sev_counts[getattr(ind, "severity", "info")] += 1
            kind_counts[_indicator_kind_for(getattr(ind, "category", ""))] += 1

        report.verdict = scoring.verdict  # type: ignore[assignment]
        report.threat_category = scoring.threat_category  # type: ignore[assignment]
        report.severity = scoring.severity  # type: ignore[assignment]
        report.scores = scoring.scores
        report.risk_score = scoring.scores.threat_score
        report.scan_status = "completed" if ok else "partial"
        report.providers = provider_statuses
        report.providers_ok = ok
        report.providers_total = len(provider_statuses)
        report.summary = self._summary(scoring, indicators_list)
        report.why = scoring.reasons[:10]
        report.evidence = [
            {"category": getattr(i, "category", ""),
             "detail": getattr(i, "detail", ""),
             "evidence": getattr(i, "evidence", {}) or {}}
            for i in indicators_list[:20]
        ]
        report.recommendations = self._recommendations(scoring, indicators_list)
        report.recommended_action = scoring.recommended_action  # type: ignore[assignment]
        report.indicators = IndicatorRollup(
            total=len(indicators_list),
            by_severity=dict(sev_counts),
            by_kind=dict(kind_counts),
            top=top,
        )
        report.urls_analyzed = urls
        report.domains_analyzed = domains
        report.attachments_analyzed = attachments
        report.completed_at = completed.isoformat()
        report.duration_ms = duration_ms
        report.touch()

        repo = ThreatReportRepository(db)
        await repo.update({"_id": report.id},
                          {"$set": report.model_dump(by_alias=True)})

        # Persist IOCs.
        ioc_repo = ThreatIndicatorRepository(db)
        iocs: list[ThreatIndicator] = []
        for ind in indicators_list:
            value = ""
            evidence = getattr(ind, "evidence", {}) or {}
            for key in ("url", "domain", "ip", "filename", "sha256"):
                if key in evidence and evidence[key]:
                    value = str(evidence[key])
                    break
                if hasattr(ind, key):
                    v = getattr(ind, key)
                    if v:
                        value = str(v)
                        break
            if not value:
                value = getattr(ind, "detail", "")[:200]
            iocs.append(ThreatIndicator(
                threat_report_id=report.id,
                user_id=report.user_id,
                kind=_indicator_kind_for(getattr(ind, "category", "")),  # type: ignore[arg-type]
                value=value,
                value_hash=sha256_hex(value),
                severity=_severity_to_ioc(getattr(ind, "severity", "info")),  # type: ignore[arg-type]
                confidence=scoring.scores.confidence,
            ))
        if iocs:
            await ioc_repo.bulk_upsert(iocs)

        await self._timeline(report.id, report.user_id, "score_computed",
                             f"threat_score={report.risk_score}")
        await self._timeline(report.id, report.user_id, "scan_completed",
                             f"verdict={report.verdict}")
        return report

    async def mark_failed(self, report: ThreatReport, *, reason: str) -> None:
        db = get_db()
        report.scan_status = "failed"
        report.summary = reason
        report.completed_at = now_utc().isoformat()
        report.touch()
        await ThreatReportRepository(db).update(
            {"_id": report.id}, {"$set": report.model_dump(by_alias=True)}
        )
        await self._timeline(report.id, report.user_id, "scan_failed", reason)

    # ---- helpers ------------------------------------------------------
    def _summary(self, scoring: ScoringResult, indicators: list) -> str:
        if scoring.verdict == "safe":
            return "No significant threats detected across configured providers."
        top = indicators[0] if indicators else None
        head = f"{scoring.verdict.replace('_', ' ').title()} " \
               f"({scoring.threat_category.replace('_', ' ')})."
        if top:
            return f"{head} Primary signal: {getattr(top, 'detail', '')}"
        return head

    def _recommendations(self, scoring: ScoringResult, indicators: list) -> list[str]:
        recs: list[str] = []
        if scoring.recommended_action == "block":
            recs.append("Block delivery and notify the recipient's security team.")
        elif scoring.recommended_action == "quarantine":
            recs.append("Quarantine the message pending review.")
        elif scoring.recommended_action == "warn_user":
            recs.append("Show an interstitial warning to the recipient before rendering.")
        cats = {getattr(i, "category", "") for i in indicators}
        if "known_malware_hash" in cats or "executable_attachment" in cats:
            recs.append("Do not open the attachment. Report to the security team.")
        if any(c in cats for c in ("typosquat_domain", "homograph_domain",
                                    "display_name_mismatch")):
            recs.append("Verify sender identity through a trusted channel before responding.")
        if "spf_fail" in cats or "dkim_fail" in cats or "dmarc_fail" in cats:
            recs.append("Do not trust identity claims — email authentication failed.")
        if not recs:
            recs.append("No user action required. Monitoring only.")
        return recs

    async def _timeline(self, report_id: str, user_id: str, kind: str, message: str) -> None:
        db = get_db()
        repo = ThreatTimelineRepository(db)
        seq = await repo.next_sequence(report_id)
        try:
            await repo.insert(ThreatTimelineEvent(
                threat_report_id=report_id,
                user_id=user_id,
                kind=kind,  # type: ignore[arg-type]
                message=message,
                sequence=seq,
            ))
        except Exception:  # pragma: no cover
            log.exception("timeline_insert_failed", report_id=report_id)


threat_report_service = ThreatReportService()
