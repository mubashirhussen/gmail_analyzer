"""Materialises validated AI output into a persisted `AIReport`."""
from __future__ import annotations

from app.core.clock import now_utc
from app.models.ai_decision import AIDecisionHistory
from app.models.ai_report import (
    AIReport,
    ConfidenceBreakdown,
    EvidenceRef,
    Recommendation,
)
from app.repositories.ai_decisions import AIDecisionHistoryRepository
from app.repositories.ai_reports import AIReportRepository


class ReportGenerationService:
    def __init__(
        self,
        reports_repo: AIReportRepository,
        history_repo: AIDecisionHistoryRepository,
    ) -> None:
        self.reports_repo = reports_repo
        self.history_repo = history_repo

    async def persist(
        self,
        *,
        report: AIReport,
        cleaned: dict,
        confidence: ConfidenceBreakdown,
        recommendations: list[Recommendation],
        educational_tips: list[str],
        started_at,
    ) -> AIReport:
        report.verdict = cleaned.get("verdict", "unknown")  # type: ignore[assignment]
        report.risk_level = cleaned.get("risk_level", "none")  # type: ignore[assignment]
        report.attack_type = cleaned.get("attack_type")
        report.likely_objective = cleaned.get("likely_objective")
        report.trust_score_adjustment = float(cleaned.get("trust_score_adjustment", 0.0))

        report.threat_summary = str(cleaned.get("threat_summary", ""))[:400]
        report.executive_summary = str(cleaned.get("executive_summary", ""))[:800]
        report.detailed_explanation = str(cleaned.get("detailed_explanation", ""))[:2000]
        report.reasoning = list(cleaned.get("reasoning", []))[:12]
        report.evidence_used = [
            EvidenceRef(**e) for e in cleaned.get("evidence_used", [])
        ][:12]
        report.possible_consequences = list(cleaned.get("possible_consequences", []))[:8]
        report.user_impact = str(cleaned.get("user_impact", ""))[:800]

        report.confidence = confidence
        report.recommendations = recommendations
        report.immediate_actions = list(cleaned.get("immediate_actions", []))[:8]
        report.long_term_recommendations = list(cleaned.get("long_term_recommendations", []))[:8]
        report.technical_notes = list(cleaned.get("technical_notes", []))[:8]
        report.educational_tips = educational_tips

        completed = now_utc()
        report.completed_at = completed.isoformat()
        report.duration_ms = int((completed - started_at).total_seconds() * 1000)
        report.status = "completed"
        report.touch()

        await self.reports_repo.update(
            {"_id": report.id},
            {"$set": report.model_dump(by_alias=True)},
        )

        await self.history_repo.insert(AIDecisionHistory(
            user_id=report.user_id,
            ai_report_id=report.id,
            threat_report_id=report.threat_report_id,
            email_id=report.email_id,
            verdict=report.verdict,
            risk_level=report.risk_level,
            confidence=report.confidence.overall,
            prompt_hash=report.prompt_hash,
            prompt_version=report.prompt_version,
            model_name=report.model_name,
            outcome="accepted" if report.validation_passed else "degraded",
            reasoning_count=len(report.reasoning),
            evidence_count=len(report.evidence_used),
            duration_ms=report.duration_ms,
        ))
        return report
