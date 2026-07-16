"""AI engine tuning knobs.

Kept in one place so ops can tweak weights, timeouts, and version
strings without hunting through the service layer.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AIEngineConfig:
    # Prompt / model provenance.
    prompt_version: str = "v1.0.0"
    default_model_provider: str = "gemini"
    default_model_name: str = "gemini-1.5-flash"
    default_model_version: str = "2024-05"

    # Guardrails.
    max_prompt_chars: int = 24_000
    llm_timeout_s: float = 45.0
    max_retries: int = 2
    retry_backoff_s: float = 1.5

    # Confidence weights (sum = 1.0).
    w_evidence: float = 0.30
    w_providers: float = 0.25
    w_model: float = 0.20
    w_completeness: float = 0.15
    w_reliability: float = 0.10

    # Validation thresholds.
    min_confidence_for_accept: float = 40.0
    max_hallucination_score: float = 0.35

    # Cache.
    ai_cache_ttl_s: int = 60 * 60 * 6  # 6h


config = AIEngineConfig()
