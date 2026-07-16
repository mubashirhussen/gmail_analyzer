"""Provider abstraction — pluggable LLM backends with fallback + retry.

Supported providers:
* openai      — OpenAI chat completions
* gemini      — Google Gemini
* azure       — Azure OpenAI
* anthropic   — Anthropic Claude
* ollama      — Local Ollama
* stub        — Deterministic offline provider used in tests / when no
                credentials are configured. Guarantees the copilot is
                always operable even in air-gapped environments.

Selection is driven by config; unknown/failed providers automatically
fall back to `stub` so the API never 5xxs the user.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
import structlog

log = structlog.get_logger(__name__)


@dataclass
class LLMResult:
    provider: str
    model: str | None
    text: str
    latency_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    raw: dict[str, Any] | None = None


class LLMProvider(Protocol):
    name: str
    model: str | None

    async def complete(self, *, system: str, user: str) -> LLMResult: ...
    async def healthy(self) -> bool: ...


# --- Stub provider (always available) -------------------------------------

class StubProvider:
    name = "stub"
    model = "guardianmail-stub-1"

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        # Deterministic evidence-only fallback: extract the CONTEXT JSON and
        # return a JSON object populated from it. This guarantees the copilot
        # produces a valid, non-hallucinated response even offline.
        payload: dict[str, Any] = {}
        try:
            idx = user.find("CONTEXT (verified GuardianMail evidence")
            end = user.find("\n\nUSER_QUESTION:")
            if idx >= 0 and end > idx:
                json_start = user.find("{", idx)
                payload = json.loads(user[json_start:end])
        except Exception:
            payload = {}

        threat = payload.get("threat_report") or {}
        indicators = payload.get("indicators") or []
        providers = payload.get("providers") or []
        missing = payload.get("missing_sections") or []

        summary = (
            f"Risk {threat.get('risk_score','?')} / verdict "
            f"{threat.get('verdict','unknown')}."
            if threat else
            "Insufficient evidence — run a GuardianMail scan first."
        )

        evidence = []
        if threat:
            evidence.append({"source": "threat_report",
                             "field": "risk_score",
                             "value": threat.get("risk_score")})
        for p in providers[:5]:
            evidence.append({"source": f"provider:{p.get('provider')}",
                             "field": "verdict",
                             "value": p.get("verdict")})

        obj = {
            "summary": summary,
            "evidence": evidence,
            "threat_indicators": [
                f"{i.get('kind')}={i.get('value')}" for i in indicators[:8]
            ],
            "ai_reasoning": (
                "Derived from verified GuardianMail threat report and "
                "provider correlation only."
            ),
            "confidence": float(threat.get("confidence") or (0.4 if threat else 0.1)),
            "recommended_action": (
                "Do not interact with the message; report to your security team."
                if threat and (threat.get("risk_score") or 0) >= 60
                else "Treat with caution and verify sender through a trusted channel."
            ),
            "educational_tip": (
                "Verify sender identity via a known channel before acting on "
                "urgent email requests."
            ),
            "related_concepts": ["Phishing", "SPF", "DKIM", "DMARC"],
        }
        if missing:
            obj["ai_reasoning"] += f" Missing evidence sections: {missing}."

        latency = int((time.perf_counter() - start) * 1000)
        return LLMResult(
            provider=self.name, model=self.model,
            text=json.dumps(obj), latency_ms=latency,
        )

    async def healthy(self) -> bool:
        return True


# --- HTTP-based providers -------------------------------------------------

class _HttpProviderBase:
    name: str = "http"
    model: str | None = None
    timeout: float = 30.0

    async def _post(self, url: str, headers: dict, json_body: dict) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, headers=headers, json=json_body)
            r.raise_for_status()
            return r.json()

    async def healthy(self) -> bool:
        return True


class OpenAIProvider(_HttpProviderBase):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini",
                 base_url: str = "https://api.openai.com/v1") -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        data = await self._post(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}",
             "Content-Type": "application/json"},
            {"model": self.model, "temperature": 0.1,
             "response_format": {"type": "json_object"},
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        latency = int((time.perf_counter() - start) * 1000)
        choice = (data.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content")) or ""
        usage = data.get("usage") or {}
        return LLMResult(
            provider=self.name, model=self.model, text=text, latency_ms=latency,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"), raw=data,
        )


class AzureOpenAIProvider(_HttpProviderBase):
    name = "azure"

    def __init__(self, api_key: str, endpoint: str, deployment: str,
                 api_version: str = "2024-06-01") -> None:
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.deployment = deployment
        self.model = deployment
        self.api_version = api_version

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        url = (f"{self.endpoint}/openai/deployments/{self.deployment}"
               f"/chat/completions?api-version={self.api_version}")
        data = await self._post(
            url,
            {"api-key": self.api_key, "Content-Type": "application/json"},
            {"temperature": 0.1,
             "response_format": {"type": "json_object"},
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        latency = int((time.perf_counter() - start) * 1000)
        choice = (data.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content")) or ""
        usage = data.get("usage") or {}
        return LLMResult(
            provider=self.name, model=self.model, text=text, latency_ms=latency,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"), raw=data,
        )


class GeminiProvider(_HttpProviderBase):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent?key={self.api_key}")
        data = await self._post(
            url, {"Content-Type": "application/json"},
            {"system_instruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": user}]}],
             "generationConfig": {"temperature": 0.1,
                                  "response_mime_type": "application/json"}},
        )
        latency = int((time.perf_counter() - start) * 1000)
        cand = (data.get("candidates") or [{}])[0]
        parts = ((cand.get("content") or {}).get("parts") or [{}])
        text = "".join(p.get("text", "") for p in parts)
        usage = data.get("usageMetadata") or {}
        return LLMResult(
            provider=self.name, model=self.model, text=text, latency_ms=latency,
            prompt_tokens=usage.get("promptTokenCount"),
            completion_tokens=usage.get("candidatesTokenCount"),
            total_tokens=usage.get("totalTokenCount"), raw=data,
        )


class AnthropicProvider(_HttpProviderBase):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-latest") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        data = await self._post(
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": self.api_key,
             "anthropic-version": "2023-06-01",
             "Content-Type": "application/json"},
            {"model": self.model, "max_tokens": 1024, "temperature": 0.1,
             "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        latency = int((time.perf_counter() - start) * 1000)
        text = "".join(p.get("text", "") for p in (data.get("content") or []))
        usage = data.get("usage") or {}
        return LLMResult(
            provider=self.name, model=self.model, text=text, latency_ms=latency,
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"), raw=data,
        )


class OllamaProvider(_HttpProviderBase):
    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = "llama3.1") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    async def complete(self, *, system: str, user: str) -> LLMResult:
        start = time.perf_counter()
        data = await self._post(
            f"{self.base_url}/api/chat", {"Content-Type": "application/json"},
            {"model": self.model, "stream": False, "format": "json",
             "options": {"temperature": 0.1},
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        latency = int((time.perf_counter() - start) * 1000)
        text = ((data.get("message") or {}).get("content")) or ""
        return LLMResult(
            provider=self.name, model=self.model, text=text,
            latency_ms=latency, raw=data,
        )


# --- Registry --------------------------------------------------------------

def _build_from_env() -> list[LLMProvider]:
    provs: list[LLMProvider] = []
    if os.getenv("OPENAI_API_KEY"):
        provs.append(OpenAIProvider(os.environ["OPENAI_API_KEY"],
                                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini")))
    if os.getenv("AZURE_OPENAI_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT") \
            and os.getenv("AZURE_OPENAI_DEPLOYMENT"):
        provs.append(AzureOpenAIProvider(
            os.environ["AZURE_OPENAI_KEY"],
            os.environ["AZURE_OPENAI_ENDPOINT"],
            os.environ["AZURE_OPENAI_DEPLOYMENT"],
        ))
    if os.getenv("GEMINI_API_KEY"):
        provs.append(GeminiProvider(os.environ["GEMINI_API_KEY"],
                                    model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash")))
    if os.getenv("ANTHROPIC_API_KEY"):
        provs.append(AnthropicProvider(os.environ["ANTHROPIC_API_KEY"],
                                       model=os.getenv("ANTHROPIC_MODEL",
                                                       "claude-3-5-sonnet-latest")))
    if os.getenv("OLLAMA_URL"):
        provs.append(OllamaProvider(os.environ["OLLAMA_URL"],
                                    model=os.getenv("OLLAMA_MODEL", "llama3.1")))
    provs.append(StubProvider())
    return provs


class ProviderRouter:
    """Priority-ordered router with retry + fallback."""

    def __init__(self, providers: list[LLMProvider] | None = None,
                 max_attempts: int = 2) -> None:
        self.providers = providers or _build_from_env()
        self.max_attempts = max_attempts

    def names(self) -> list[str]:
        return [p.name for p in self.providers]

    def resolve(self, preferred: str | None) -> list[LLMProvider]:
        if not preferred:
            return list(self.providers)
        head = [p for p in self.providers if p.name == preferred]
        tail = [p for p in self.providers if p.name != preferred]
        return head + tail if head else list(self.providers)

    async def complete(self, *, system: str, user: str,
                       preferred: str | None = None) -> LLMResult:
        last_err: Exception | None = None
        for provider in self.resolve(preferred):
            for attempt in range(1, self.max_attempts + 1):
                try:
                    return await provider.complete(system=system, user=user)
                except Exception as exc:
                    last_err = exc
                    log.warning("copilot.provider_failed",
                                provider=provider.name,
                                attempt=attempt, error=str(exc))
                    await asyncio.sleep(0.2 * attempt)
        # Stub is always last — this only fires if it also raised.
        raise RuntimeError(f"all providers failed: {last_err}")


provider_router = ProviderRouter()
