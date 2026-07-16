"""Thin adapter around the Gemini API with strict JSON-mode enforcement.

Design notes
------------
* This module is the *only* place that talks to a third-party LLM. All
  other AI services depend on the abstract `LLMClient` protocol, which
  keeps prompt building, validation, and persistence decoupled from the
  provider.
* When `GEMINI_API_KEY` is absent we return an explicit
  `LLMUnavailable` result — the engine then degrades gracefully into a
  deterministic heuristic instead of fabricating a verdict.
* Retries use exponential backoff and treat malformed JSON as a
  recoverable error (the model occasionally emits stray prose).
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.services.ai.config import config

log = get_logger(__name__)

try:  # pragma: no cover - runtime optional dependency
    import google.generativeai as genai
    if settings.GEMINI_API_KEY:
        genai.configure(api_key=settings.GEMINI_API_KEY)
    _GENAI_OK = True
except Exception:  # noqa: BLE001
    genai = None  # type: ignore[assignment]
    _GENAI_OK = False


class LLMError(RuntimeError):
    """Raised when the model returns an unrecoverable failure."""


class LLMUnavailable(RuntimeError):
    """Raised when no LLM provider is configured / reachable."""


class LLMTimeout(LLMError):
    pass


class LLMMalformed(LLMError):
    pass


class LLMRateLimited(LLMError):
    pass


@dataclass(slots=True)
class LLMResponse:
    text: str
    parsed: dict[str, Any]
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    model_name: str = ""
    model_version: str = ""


class GeminiClient:
    """Async Gemini wrapper that always returns parsed JSON."""

    def __init__(
        self,
        model_name: str | None = None,
        model_version: str | None = None,
    ) -> None:
        self.model_name = model_name or config.default_model_name
        self.model_version = model_version or config.default_model_version

    async def complete_json(
        self, *, system: str, user: str, timeout_s: float | None = None,
    ) -> LLMResponse:
        if not _GENAI_OK or not settings.GEMINI_API_KEY:
            raise LLMUnavailable("gemini api key missing")

        timeout = timeout_s or config.llm_timeout_s
        last_err: Exception | None = None
        for attempt in range(config.max_retries + 1):
            try:
                model = genai.GenerativeModel(  # type: ignore[union-attr]
                    self.model_name, system_instruction=system,
                )
                coro = model.generate_content_async(
                    user,
                    generation_config={"response_mime_type": "application/json"},
                )
                resp = await asyncio.wait_for(coro, timeout=timeout)
                text = (resp.text or "").strip()
                if not text:
                    raise LLMMalformed("empty response")
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise LLMMalformed(f"non-json response: {exc}") from exc
                return LLMResponse(
                    text=text,
                    parsed=parsed,
                    model_name=self.model_name,
                    model_version=self.model_version,
                )
            except asyncio.TimeoutError as exc:
                last_err = LLMTimeout(f"attempt {attempt} timed out")
                log.warning("ai.llm.timeout", attempt=attempt, error=str(exc))
            except LLMMalformed as exc:
                last_err = exc
                log.warning("ai.llm.malformed", attempt=attempt, error=str(exc))
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if "rate" in msg or "quota" in msg or "429" in msg:
                    last_err = LLMRateLimited(str(exc))
                else:
                    last_err = LLMError(str(exc))
                log.warning("ai.llm.error", attempt=attempt, error=str(exc))
            await asyncio.sleep(config.retry_backoff_s * (attempt + 1))
        assert last_err is not None
        raise last_err
