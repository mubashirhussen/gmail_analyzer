"""ThreatCorrelationService — the Phase 17 orchestrator.

Fans out to every detection subsystem in parallel where safe, correlates
their signals into a single risk score, classifies the verdict, produces
a recommendation, and persists a `DetectionResult` (plus fraud indicators).

The service reads existing GuardianMail artifacts (email, headers, urls,
attachments) but never mutates them.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import structlog

from app.database.mongodb import get_db
from app.models.detection import DetectionResult
from app.repositories.detection import DetectionRepository
from app.repositories.emails import EmailRepository
from app.services.detection.ai_generated import ai_generated_detector
from app.services.detection.behavior_analysis import behavior_analysis_service
from app.services.detection.domain_intelligence import domain_intelligence_service
from app.services.detection.fraud_detection import fraud_detection_service
from app.services.detection.header_analysis import header_analysis_service
from app.services.detection.language_analysis import language_analysis_service
from app.services.detection.recommendation import recommendation_service
from app.services.detection.url_intelligence import url_intelligence_service

log = structlog.get_logger(__name__)


_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)


def _domain_of(addr: str | None) -> str:
    if not addr:
        return ""
    m = re.search(r"@([\w\.-]+)", addr)
    return m.group(1).lower() if m else ""


def _classify(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "safe"


def _confidence(signals_ct: int, evidence_ct: int) -> float:
    base = min(1.0, 0.4 + 0.05 * signals_ct + 0.05 * evidence_ct)
    return round(base, 3)


def _impact(fraud_findings: list[dict[str, Any]], score: float) -> str:
    if any(f.get("kind") == "bec_ceo_fraud" for f in fraud_findings):
        return "critical"
    if any(f.get("severity") == "high" for f in fraud_findings):
        return "high"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


class ThreatCorrelationService:
    async def analyze(
        self,
        *,
        user_id: str,
        email_id: str | None = None,
        threat_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        db = get_db()

        subject = (payload or {}).get("subject")
        sender = (payload or {}).get("sender")
        body = (payload or {}).get("body")
        headers = (payload or {}).get("headers") or {}
        urls = list((payload or {}).get("urls") or [])
        attachments = list((payload or {}).get("attachments") or [])

        # Enrich from stored email when possible.
        if email_id:
            email_doc = await EmailRepository(db).find_by_id(email_id)
            if email_doc and email_doc.get("user_id") == user_id:
                subject = subject or email_doc.get("subject")
                sender = sender or email_doc.get("from_address")
                body = body or email_doc.get("body_text") or email_doc.get("body_html")
                headers = headers or (email_doc.get("headers") or {})
                if not urls and body:
                    urls = _URL_RE.findall(body)[:25]

        # Parallel-safe subsystems (all CPU-bound / stateless).
        header_task = asyncio.to_thread(header_analysis_service.analyze, headers)
        domain_task = asyncio.to_thread(
            domain_intelligence_service.analyze, _domain_of(sender)
        )
        url_task = asyncio.to_thread(url_intelligence_service.analyze, urls)
        lang_task = asyncio.to_thread(language_analysis_service.analyze, subject, body)
        ai_task = asyncio.to_thread(ai_generated_detector.analyze, subject, body)
        fraud_task = asyncio.to_thread(
            fraud_detection_service.scan,
            subject=subject, body=body, sender=sender,
        )
        # Behaviour analysis writes to Mongo, keep it async.
        behavior_task = behavior_analysis_service.evaluate(
            user_id=user_id, sender=sender, subject=subject,
            verdict=None, flagged=False,
        )

        header, domain, urls_res, lang, ai_gen, fraud, behavior = await asyncio.gather(
            header_task, domain_task, url_task, lang_task, ai_task,
            fraud_task, behavior_task,
        )

        # Correlated risk score.
        score = 0.0
        score += float(header.get("score", 0)) * 0.9
        score += float(domain.get("score", 0)) * 0.8
        score += sum(float(u.get("score", 0)) for u in urls_res) * 0.4
        score += float(lang.get("score", 0)) * 0.9
        score += sum(float(f.get("weight", 0)) for f in fraud) * 1.0
        score += float(ai_gen.get("score", 0)) * 0.6
        score += float(behavior.get("score", 0))

        # Attachment quick heuristics.
        att_signals: list[str] = []
        for a in attachments:
            name = (a.get("filename") or "").lower()
            if re.search(r"\.(exe|scr|bat|cmd|vbs|js|jse|ps1|hta|jar|msi)$", name):
                att_signals.append(f"exec_attachment:{name}")
                score += 25
            if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|zip)$", name):
                att_signals.append(f"double_extension:{name}")
                score += 20
            if (a.get("mime") or "") in ("application/x-msdownload",
                                          "application/x-msi"):
                att_signals.append(f"exec_mime:{name}")
                score += 20

        score = max(0.0, min(100.0, score))
        classification = _classify(score)
        categories = list(dict.fromkeys(lang.get("categories") or []))
        if any(f.get("kind") == "bec_ceo_fraud" for f in fraud):
            categories.insert(0, "bec_ceo_fraud")
        if domain.get("flags"):
            if any(f.startswith("typosquat") or f.startswith("brand_in_subdomain")
                   for f in domain["flags"]):
                categories.append("brand_impersonation")

        signals: list[dict[str, Any]] = []
        signals.append({"source": "header", "flags": header.get("anomalies", []),
                        "score": header.get("score", 0)})
        signals.append({"source": "domain", "flags": domain.get("flags", []),
                        "score": domain.get("score", 0)})
        signals.append({"source": "language", "flags": lang.get("categories", []),
                        "score": lang.get("score", 0)})
        signals.append({"source": "behavior", "flags": behavior.get("signals", []),
                        "score": behavior.get("score", 0)})
        signals.append({"source": "ai_generated", "flags": ai_gen.get("flags", []),
                        "score": ai_gen.get("score", 0)})
        if att_signals:
            signals.append({"source": "attachments", "flags": att_signals,
                            "score": min(60.0, len(att_signals) * 20)})
        for u in urls_res:
            signals.append({"source": "url", "url": u.get("url"),
                            "flags": u.get("flags", []),
                            "score": u.get("score", 0)})

        confidence = _confidence(
            signals_ct=sum(1 for s in signals if s.get("flags")),
            evidence_ct=len(fraud) + len(urls_res),
        )
        impact = _impact(fraud, score)
        complexity = ("high" if len([s for s in signals if s.get("flags")]) >= 5
                       else "medium" if score >= 40 else "low")

        recommendation, actions = recommendation_service.recommend(
            classification=classification, risk_score=score, fraud_findings=fraud,
        )

        elapsed = int((time.perf_counter() - started) * 1000)
        detection = DetectionResult(
            user_id=user_id, email_id=email_id, threat_id=threat_id,
            subject=(subject or "")[:1000], sender=(sender or "")[:320],
            classification=classification, risk_score=round(score, 2),
            confidence=confidence,
            attack_complexity=complexity, potential_impact=impact,
            categories=categories, signals=signals,
            fraud_findings=fraud,
            behavior=behavior, language=lang, header=header, domain=domain,
            urls=urls_res, ai_generated=ai_gen,
            recommendation=recommendation, recommendation_actions=actions,
            execution_ms=elapsed,
        )

        repo = DetectionRepository(db)
        try:
            await repo.insert_one(detection.to_mongo())
        except Exception as exc:
            log.warning("detection.persist_failed", error=str(exc))

        try:
            await fraud_detection_service.persist(
                user_id=user_id, detection_id=detection.id,
                email_id=email_id, findings=fraud,
            )
        except Exception:
            pass

        log.info(
            "detection.analyzed",
            user_id=user_id, email_id=email_id,
            classification=classification, risk_score=score,
            categories=categories, ms=elapsed,
        )
        return detection.model_dump(by_alias=True)


threat_correlation_service = ThreatCorrelationService()
