"""Provider contract for the Threat Intelligence Engine.

Every external source (Google Safe Browsing, VirusTotal, URLScan,
PhishTank, URLHaus, RDAP, AbuseIPDB, DNS/SSL probes) implements this
same interface. Isolation guarantees:

* One provider's failure never blocks another — `run()` catches all
  exceptions and returns a `ProviderOutcome`.
* Every call is timed and rate-limit / circuit-breaker aware.
* Cached results (Redis + `provider_results` collection) bypass the
  network entirely.
"""
from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from app.core.logging import get_logger
from app.services.threat.config import (
    PROVIDER_CACHE_TTL,
    PROVIDER_MAX_RETRIES,
    PROVIDER_TIMEOUT_S,
)

log = get_logger(__name__)

Verdict = Literal["clean", "suspicious", "malicious", "unknown"]
Status = Literal["ok", "skipped", "error", "timeout", "rate_limited", "unavailable"]
ArtifactKind = Literal["url", "domain", "ip", "file_hash"]


@dataclass(slots=True)
class ProviderOutcome:
    provider: str
    artifact_kind: ArtifactKind
    artifact_value: str
    status: Status = "ok"
    verdict: Verdict = "unknown"
    score: float | None = None
    normalized_score: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None


class BaseProvider(abc.ABC):
    """One provider = one class instance shared across the process."""

    slug: str = ""
    kinds: tuple[ArtifactKind, ...] = ()

    @property
    def timeout_s(self) -> float:
        return PROVIDER_TIMEOUT_S.get(self.slug, 6.0)

    @property
    def cache_ttl_s(self) -> int:
        return PROVIDER_CACHE_TTL.get(self.slug, 3600)

    # -------- lifecycle -----------------------------------------------
    def enabled(self) -> bool:
        """Providers requiring an API key override this."""
        return True

    @abc.abstractmethod
    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        ...

    # -------- public entry point -------------------------------------
    async def run(
        self,
        client: httpx.AsyncClient,
        artifact_kind: ArtifactKind,
        artifact_value: str,
    ) -> ProviderOutcome:
        if artifact_kind not in self.kinds:
            return ProviderOutcome(self.slug, artifact_kind, artifact_value, status="skipped")
        if not self.enabled():
            return ProviderOutcome(self.slug, artifact_kind, artifact_value, status="skipped",
                                   error_code="disabled")
        started = time.perf_counter()
        attempt = 0
        last: ProviderOutcome | None = None
        while attempt <= PROVIDER_MAX_RETRIES:
            attempt += 1
            try:
                outcome = await asyncio.wait_for(
                    self._call(client, artifact_kind, artifact_value),
                    timeout=self.timeout_s,
                )
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                return outcome
            except asyncio.TimeoutError:
                last = ProviderOutcome(
                    self.slug, artifact_kind, artifact_value,
                    status="timeout", error_code="timeout",
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                status: Status = "rate_limited" if code == 429 else "error"
                last = ProviderOutcome(
                    self.slug, artifact_kind, artifact_value,
                    status=status, http_status=code,
                    error_code=f"http_{code}", error_message=str(e)[:200],
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
                if status == "rate_limited":
                    break  # respect provider back-off
            except (httpx.HTTPError, OSError) as e:
                last = ProviderOutcome(
                    self.slug, artifact_kind, artifact_value,
                    status="unavailable", error_code=type(e).__name__,
                    error_message=str(e)[:200],
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
            except Exception as e:  # never let a provider blow up the engine
                log.exception("provider_unhandled", provider=self.slug)
                last = ProviderOutcome(
                    self.slug, artifact_kind, artifact_value,
                    status="error", error_code="unhandled",
                    error_message=str(e)[:200],
                    latency_ms=int((time.perf_counter() - started) * 1000),
                )
                break
            await asyncio.sleep(0.2 * attempt)
        return last or ProviderOutcome(self.slug, artifact_kind, artifact_value, status="error")
