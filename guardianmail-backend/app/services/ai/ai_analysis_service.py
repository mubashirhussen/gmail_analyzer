"""AI Analysis orchestrator.

Pipeline (see docs/MODULE_06_AI_ENGINE.md for the full diagram):

    threat_report -> prompt_builder -> llm -> validator ->
      confidence -> recommendation -> educational -> persistence ->
      decision_history

The engine is idempotent per (threat_report_id, prompt_hash): re-analysis
with the same inputs returns the cached row unless `force=True`.
"""
from __future__ import annotations

from datetime import datetime

from app.core.clock import now_utc
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.database.redis import redis_client
from app.models.ai_report import AIReport, ConfidenceBreakdown
from app.repositories.ai_decisions import AIDecisionHistoryRepository
from app.repositories.ai_prompts import AIPromptRepository
from app.repositories.ai_reports import AIReportRepository
from app.repositories.threats import ThreatReportRepository
from app.services.ai.ai_validation_service import AIValidationService
from app.services.ai.confidence_service import ConfidenceService
from app.services.ai.config import config
from app.services.ai.educational_content_service import EducationalContentService
from app.services.ai.llm_client import (
    GeminiClient,
    LLMError,
    LLMRateLimited,
    LLMTimeout,
    LLMUnavailable,
)
from app.services.ai.prompt_builder_service import PromptBuilderService
from app.services.ai.recommendation_service import RecommendationService
from app.services.ai.redis_keys import ai_lock_key
from app.services.ai.report_generation_service import ReportGenerationService

log = get_logger(__name__)


class AIAnalysisService:
    def __init__(self) -> None:
        self.prompt_builder = PromptBuilderService()
        self.validator = AIValidationService()
        self.confidence = ConfidenceService()
        self.recommender = RecommendationService()
        self.education = EducationalContentService()
        self.llm = GeminiClient()

    # ------------------------------------------------------------------ api
    async def analyze(
        self,
        *,
        user_id: str,
        threat_report_id: str,
        channel: str = "email",
        triggered_by: str = "user",
        force: bool = False,
    ) -> AIReport:
        db = get_db()
        threats_repo = ThreatReportRepository(db)
        reports_repo = AIReportRepository(db)
        history_repo = AIDecisionHistoryRepository(db)
        gen_service = ReportGenerationService(reports_repo, history_repo)

        threat_report = await threats_repo.find_by_id(threat_report_id)
        if not threat_report or threat_report.user_id != user_id:
            raise NotFoundError(f"threat report not found: {threat_report_id}")

        # Cache short-circuit.
        if not force:
            existing = await reports_repo.latest_for_threat(threat_report_id)
            if existing and existing.status == "completed":
                return existing

        # Prevent concurrent runs for the same report.
        lock = ai_lock_key(threat_report_id)
        acquired = await redis_client.set_nx(lock, "1", ex=120)
        try:
            built = self.prompt_builder.build(threat_report)
            started_at = now_utc()
            report = AIReport(
                user_id=user_id,
                threat_report_id=threat_report_id,
                email_id=threat_report.email_id,
                channel=channel,  # type: ignore[arg-type]
                triggered_by=triggered_by,  # type: ignore[arg-type]
                status="running",
                started_at=started_at.isoformat(),
                model_provider=config.default_model_provider,
                model_name=self.llm.model_name,
                model_version=self.llm.model_version,
                prompt_version=built.prompt_version,
                prompt_hash=built.prompt_hash,
            )
            await reports_repo.insert(report)

            parsed, model_used, model_version, prompt_tokens, completion_tokens, degraded = (
                await self._invoke_llm(built.system, built.user)
            )
            report.model_name = model_used or report.model_name
            report.model_version = model_version or report.model_version
            report.prompt_tokens = prompt_tokens
            report.completion_tokens = completion_tokens

            validation = self.validator.validate(parsed, threat_report)
            report.validation_passed = validation.passed
            report.validation_errors = validation.errors
            report.hallucination_score = validation.hallucination_score

            confidence = self.confidence.compute(
                threat_report=threat_report,
                model_confidence=float(validation.cleaned.get("model_confidence", 0.0)),
                evidence_used_count=len(validation.cleaned.get("evidence_used", [])),
                reasoning_count=len(validation.cleaned.get("reasoning", [])),
                validation_passed=validation.passed,
            )

            recs = self.recommender.build(
                risk_level=validation.cleaned.get("risk_level", "none"),
                immediate=validation.cleaned.get("immediate_actions", []),
                long_term=validation.cleaned.get("long_term_recommendations", []),
                educational=validation.cleaned.get("educational_tips", []),
                technical=validation.cleaned.get("technical_notes", []),
            )
            edu = self.education.enrich(
                verdict=validation.cleaned.get("verdict", "unknown"),
                base_tips=validation.cleaned.get("educational_tips", []),
            )

            if degraded:
                report.status = "degraded"
                report.error_code = "llm_unavailable"

            await gen_service.persist(
                report=report,
                cleaned=validation.cleaned,
                confidence=confidence,
                recommendations=recs,
                educational_tips=edu,
                started_at=started_at,
            )
            log.info(
                "ai.analysis.completed",
                report_id=report.id, verdict=report.verdict,
                risk_level=report.risk_level, confidence=confidence.overall,
                validation_passed=validation.passed,
                hallucination_score=validation.hallucination_score,
                duration_ms=report.duration_ms,
            )
            return report
        finally:
            if acquired:
                await redis_client.delete(lock)

    # -------------------------------------------------------------- helpers
    async def _invoke_llm(self, system: str, user: str):
        """Call LLM with graceful fallback into a deterministic heuristic."""
        try:
            resp = await self.llm.complete_json(system=system, user=user)
            return (
                resp.parsed, resp.model_name, resp.model_version,
                resp.prompt_tokens, resp.completion_tokens, False,
            )
        except LLMUnavailable:
            log.warning("ai.llm.unavailable.using_heuristic")
            return self._heuristic_fallback(user), "heuristic", "v1", None, None, True
        except (LLMTimeout, LLMRateLimited) as exc:
            log.warning("ai.llm.transient", error=str(exc))
            return self._heuristic_fallback(user), "heuristic", "v1", None, None, True
        except LLMError as exc:
            log.error("ai.llm.error", error=str(exc))
            return self._heuristic_fallback(user), "heuristic", "v1", None, None, True

    def _heuristic_fallback(self, user_prompt: str) -> dict:
        """Deterministic decision when the LLM is unreachable.

        We intentionally return `unknown` verdict + low confidence so the
        UI can flag that additional verification is required rather than
        showing a fabricated verdict.
        """
        return {
            "verdict": "unknown",
            "risk_level": "medium",
            "attack_type": None,
            "likely_objective": None,
            "trust_score_adjustment": 0.0,
            "threat_summary": "AI reasoner unavailable — deterministic fallback used.",
            "executive_summary": (
                "The AI analysis engine could not reach the language model. "
                "The engine returned a conservative, uncertain verdict based on the "
                "upstream threat report only. Additional verification is required."
            ),
            "detailed_explanation": (
                "Because no model response was available, this report does not "
                "include model-generated reasoning. The upstream Threat Intelligence "
                "Engine's scores and indicators should be trusted over this fallback."
            ),
            "reasoning": ["LLM provider unavailable — falling back to heuristic."],
            "evidence_used": [],
            "possible_consequences": [
                "Acting on this message without human review may be risky.",
            ],
            "user_impact": "Delay action until an analyst confirms the verdict.",
            "model_confidence": 15.0,
            "immediate_actions": [
                "Do not click links or download attachments until reviewed.",
            ],
            "long_term_recommendations": [
                "Re-run analysis once the AI engine is available.",
            ],
            "educational_tips": [
                "Fallback reports mean the AI could not respond — always seek human review.",
            ],
            "technical_notes": [
                "LLM invocation failed after configured retries.",
            ],
        }
