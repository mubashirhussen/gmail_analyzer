"""Prompt Builder.

Transforms a `ThreatReport` (Module 5) plus its linked indicators into a
compact, deterministic prompt suitable for strict-JSON LLM output.

Design principles
-----------------
* Deterministic — the same threat report produces the same prompt bytes
  (stable ordering, no timestamps, sorted collections). This keeps
  `prompt_hash` a useful fingerprint for caching and audit.
* Grounded — the prompt lists every indicator explicitly so the model
  can only cite evidence that actually exists (prevents hallucination).
* Bounded — the payload is truncated to `max_prompt_chars` to protect
  against runaway token bills and provider hard limits.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.models.threat import ThreatReport
from app.services.ai.config import config

_SYSTEM_TEMPLATE = """You are GuardianMail's Explainable Security Analyst.

Your job is to review a structured Threat Report produced by an upstream
Threat Intelligence Engine and return a *strict JSON* security decision.

Follow every rule below without deviation:

1. NEVER invent facts. Every claim you make MUST reference an indicator,
   provider result, header analysis, or score already present in the
   provided report. If a signal is missing, say so explicitly.
2. Return ONLY JSON matching the schema at the bottom of this prompt.
   No prose, no markdown fences, no commentary.
3. Reasoning MUST be short, factual bullets grounded in the evidence.
4. Recommendations MUST be actionable ("do X", "avoid Y"), never vague.
5. Educational tips MUST teach the user how attacks like this work.
   Avoid fear-based language.
6. Confidence values live in [0, 100]. `trust_score_adjustment` lives
   in [-40, +20] and reflects how much this decision should nudge the
   sender's long-term trust score.
7. `verdict` MUST be one of: safe, suspicious, spam, phishing,
   credential_theft, business_email_compromise, malware, invoice_fraud,
   payment_scam, identity_theft, fake_login, qr_phishing, unknown.
8. `risk_level` MUST be one of: none, low, medium, high, critical.

Schema:
{{
  "verdict": "<one of the allowed verdicts>",
  "risk_level": "<none|low|medium|high|critical>",
  "attack_type": "<short label or null>",
  "likely_objective": "<what the attacker wants or null>",
  "trust_score_adjustment": <number in [-40, 20]>,
  "threat_summary": "<one sentence>",
  "executive_summary": "<2-3 sentences for a non-technical reader>",
  "detailed_explanation": "<4-8 sentences for a technical reader>",
  "reasoning": ["<grounded bullet>", "..."],
  "evidence_used": [
    {{"category": "<indicator category>", "detail": "<short quote>",
      "severity": "<info|low|medium|high|critical>", "weight": <0..1>}}
  ],
  "possible_consequences": ["<what happens if user acts>"],
  "user_impact": "<one paragraph>",
  "model_confidence": <0..100>,
  "immediate_actions": ["<do this now>"],
  "long_term_recommendations": ["<what to change going forward>"],
  "educational_tips": ["<how to spot similar attacks>"],
  "technical_notes": ["<optional expert notes>"]
}}
"""


@dataclass(slots=True)
class BuiltPrompt:
    system: str
    user: str
    prompt_hash: str
    prompt_version: str


class PromptBuilderService:
    def __init__(self, prompt_version: str | None = None) -> None:
        self.prompt_version = prompt_version or config.prompt_version

    # --------------------------------------------------------------- public
    def build(self, report: ThreatReport) -> BuiltPrompt:
        payload = self._serialize_report(report)
        user_prompt = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                 separators=(",", ":"))
        if len(user_prompt) > config.max_prompt_chars:
            user_prompt = user_prompt[: config.max_prompt_chars]
        system = _SYSTEM_TEMPLATE
        digest = hashlib.sha256(
            (self.prompt_version + "|" + system + "|" + user_prompt).encode("utf-8")
        ).hexdigest()
        return BuiltPrompt(
            system=system, user=user_prompt,
            prompt_hash=digest, prompt_version=self.prompt_version,
        )

    # --------------------------------------------------------------- helpers
    def _serialize_report(self, r: ThreatReport) -> dict:
        return {
            "threat_report_id": r.id,
            "verdict_hint": r.verdict,
            "threat_category_hint": r.threat_category,
            "severity": r.severity,
            "scores": {
                "threat_score": round(r.scores.threat_score, 2),
                "trust_score": round(r.scores.trust_score, 2),
                "security_score": round(r.scores.security_score, 2),
                "confidence": round(r.scores.confidence, 3),
            },
            "coverage": {
                "providers_ok": r.providers_ok,
                "providers_total": r.providers_total,
                "urls_analyzed": r.urls_analyzed,
                "domains_analyzed": r.domains_analyzed,
                "attachments_analyzed": r.attachments_analyzed,
            },
            "providers": sorted(
                [
                    {"provider": p.provider, "status": p.status,
                     "error_code": p.error_code}
                    for p in r.providers
                ],
                key=lambda x: x["provider"],
            ),
            "indicators_rollup": {
                "total": r.indicators.total,
                "by_severity": dict(sorted(r.indicators.by_severity.items())),
                "by_kind": dict(sorted(r.indicators.by_kind.items())),
                "top": r.indicators.top,
            },
            "evidence": r.evidence,
            "why": r.why,
            "engine_summary": r.summary,
            "engine_recommendation": r.recommended_action,
        }
