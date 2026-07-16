"""CopilotService — orchestrates context, prompt, LLM, validation, storage.

Single entry point used by the API layer. Enforces prompt-injection safety,
evidence-only answers, and short investigation memory.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from app.models.copilot import CopilotMessage
from app.services.copilot.context_service import context_service
from app.services.copilot.conversation_service import conversation_service
from app.services.copilot.educational_service import educational_service
from app.services.copilot.prompt_builder import (
    SYSTEM_PROMPT,
    build_explain_question,
    build_summarize_question,
    build_user_prompt,
)
from app.services.copilot.providers import provider_router
from app.services.copilot.validator import response_validator

log = structlog.get_logger(__name__)

# Very-defensive prompt-injection scrubber for user questions.
_INJECT_PAT = re.compile(
    r"(ignore\s+(all\s+)?previous|disregard\s+the\s+system|reveal\s+the\s+prompt|"
    r"you\s+are\s+now|jailbreak|developer\s+mode)",
    re.I,
)


def _sanitize_question(q: str) -> str:
    q = (q or "").strip()
    if len(q) > 2000:
        q = q[:2000]
    # Replace suspicious directives with a neutral marker rather than
    # dropping them entirely, so the copilot can decline politely.
    return _INJECT_PAT.sub("[filtered]", q)


class CopilotService:
    async def _answer(
        self,
        *,
        user_id: str,
        question: str,
        scope: dict[str, Any],
        conversation_id: str | None,
        provider: str | None,
    ) -> dict[str, Any]:
        question = _sanitize_question(question)
        ctx = await context_service.build(user_id=user_id, scope=scope)

        conv = await conversation_service.get_or_create(
            user_id=user_id, conversation_id=conversation_id,
            scope=scope, provider=provider,
        )
        prior = await conversation_service.recent_turns(conv.id)

        user_msg = CopilotMessage(
            conversation_id=conv.id, user_id=user_id,
            role="user", content=question,
        )
        await conversation_service.append(user_msg)

        # Refuse cleanly if there is nothing to explain.
        if not ctx.has_anchor:
            structured = {
                "summary": (
                    "I cannot answer without a GuardianMail scan or threat "
                    "report in scope. Please run an analysis first."
                ),
                "evidence": [],
                "threat_indicators": [],
                "ai_reasoning": "No verified evidence available for this scope.",
                "confidence": 0.0,
                "recommended_action": "Trigger a scan on the message or URL, then retry.",
                "educational_tip": educational_service.lookup("safe_browsing") or "",
                "related_concepts": ["Phishing", "Safe Browsing"],
            }
            asst = CopilotMessage(
                conversation_id=conv.id, user_id=user_id, role="assistant",
                content=structured["summary"], provider="none",
                validation={"ok": False, "issues": ["no_evidence_anchor"]},
                structured=structured, evidence_refs=[], latency_ms=0,
            )
            await conversation_service.append(asst)
            return {
                "conversation_id": conv.id, "message_id": asst.id,
                "provider": "none", "model": None, "latency_ms": 0,
                "validation": asst.validation, **structured,
            }

        prompt = build_user_prompt(question=question, ctx=ctx, prior_turns=prior)

        try:
            llm = await provider_router.complete(
                system=SYSTEM_PROMPT, user=prompt, preferred=provider,
            )
        except Exception as exc:
            log.error("copilot.llm_failed", error=str(exc))
            raise

        structured, report = response_validator.validate(llm.text, ctx)

        # Enrich related_concepts with curated definitions where possible.
        concepts = list(structured.get("related_concepts") or [])[:6]
        structured["related_concepts"] = concepts

        evidence_refs = ctx.evidence_refs()

        asst = CopilotMessage(
            conversation_id=conv.id, user_id=user_id, role="assistant",
            content=structured.get("summary", ""),
            provider=llm.provider, model=llm.model,
            latency_ms=llm.latency_ms,
            prompt_tokens=llm.prompt_tokens,
            completion_tokens=llm.completion_tokens,
            total_tokens=llm.total_tokens,
            validation=report.as_dict(),
            evidence_refs=evidence_refs,
            structured=structured,
        )
        await conversation_service.append(asst)

        return {
            "conversation_id": conv.id,
            "message_id": asst.id,
            "provider": llm.provider,
            "model": llm.model,
            "latency_ms": llm.latency_ms,
            "validation": report.as_dict(),
            "summary": structured.get("summary", ""),
            "evidence": structured.get("evidence", []),
            "threat_indicators": structured.get("threat_indicators", []),
            "ai_reasoning": structured.get("ai_reasoning", ""),
            "confidence": float(structured.get("confidence", 0.0)),
            "recommended_action": structured.get("recommended_action", ""),
            "educational_tip": structured.get("educational_tip", ""),
            "related_concepts": structured.get("related_concepts", []),
        }

    async def chat(self, *, user_id: str, question: str, scope: dict[str, Any],
                   conversation_id: str | None = None,
                   provider: str | None = None) -> dict[str, Any]:
        return await self._answer(
            user_id=user_id, question=question, scope=scope,
            conversation_id=conversation_id, provider=provider,
        )

    async def explain(self, *, user_id: str, scope: dict[str, Any],
                      aspect: str, provider: str | None = None) -> dict[str, Any]:
        return await self._answer(
            user_id=user_id, question=build_explain_question(aspect),
            scope=scope, conversation_id=None, provider=provider,
        )

    async def summarize(self, *, user_id: str, scope: dict[str, Any],
                        style: str, provider: str | None = None) -> dict[str, Any]:
        return await self._answer(
            user_id=user_id, question=build_summarize_question(style),
            scope=scope, conversation_id=None, provider=provider,
        )


copilot_service = CopilotService()
