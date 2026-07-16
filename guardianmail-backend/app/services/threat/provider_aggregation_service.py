"""Provider fan-out with caching + per-artefact isolation.

The aggregator is intentionally dumb — it schedules providers and
persists their outputs. Score interpretation lives in `score_service`.
"""
from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.models.provider_result import ProviderResult
from app.repositories.provider_results import ProviderResultRepository
from app.services.threat.normalizer import sha256_hex
from app.services.threat.providers import ALL, BaseProvider, ProviderOutcome

log = get_logger(__name__)


class ProviderAggregationService:
    """Runs providers for a bag of (kind, value) artefacts."""

    def __init__(self, providers: Iterable[BaseProvider] | None = None) -> None:
        self._providers = tuple(providers or ALL)

    # -------- public API ------------------------------------------------
    async def scan_artefacts(
        self,
        artefacts: Iterable[tuple[str, str]],
        *,
        threat_report_id: str | None,
        user_id: str | None,
        force: bool = False,
    ) -> list[ProviderOutcome]:
        """artefacts: iterable of (kind, canonical_value)."""
        repo = ProviderResultRepository(get_db())
        outcomes: list[ProviderOutcome] = []
        async with httpx.AsyncClient(
            headers={"User-Agent": "guardianmail-threat-engine/1.0"},
            follow_redirects=True,
        ) as client:
            tasks: list[asyncio.Task] = []
            plan: list[tuple[BaseProvider, str, str, str]] = []
            for kind, value in artefacts:
                if not value:
                    continue
                for provider in self._providers:
                    if kind not in provider.kinds or not provider.enabled():
                        continue
                    plan.append((provider, kind, value, sha256_hex(f"{provider.slug}:{kind}:{value}")))
            # Cache lookup phase (parallel).
            cached_map: dict[str, ProviderResult | None] = {}
            if not force and plan:
                cached = await asyncio.gather(*(
                    repo.cached(
                        provider=p.slug,
                        artifact_hash=sha256_hex(v),
                        ttl_seconds=p.cache_ttl_s,
                    )
                    for p, _k, v, _h in plan
                ))
                for (p, k, v, _h), c in zip(plan, cached):
                    cached_map[f"{p.slug}:{k}:{v}"] = c

            for provider, kind, value, _h in plan:
                key = f"{provider.slug}:{kind}:{value}"
                cached_row = cached_map.get(key)
                if cached_row is not None:
                    outcomes.append(ProviderOutcome(
                        provider=provider.slug,
                        artifact_kind=kind,  # type: ignore[arg-type]
                        artifact_value=value,
                        status="ok",
                        verdict=cached_row.verdict,
                        normalized_score=cached_row.normalized_score,
                        raw=cached_row.raw,
                        latency_ms=cached_row.latency_ms or 0,
                    ))
                    continue
                tasks.append(asyncio.create_task(provider.run(client, kind, value)))  # type: ignore[arg-type]
            if tasks:
                fresh = await asyncio.gather(*tasks, return_exceptions=False)
                outcomes.extend(fresh)
                # Persist for cache + audit.
                await self._persist(repo, fresh, threat_report_id=threat_report_id, user_id=user_id)
        return outcomes

    # -------- helpers ---------------------------------------------------
    async def _persist(
        self,
        repo: ProviderResultRepository,
        outcomes: list[ProviderOutcome],
        *,
        threat_report_id: str | None,
        user_id: str | None,
    ) -> None:
        rows: list[ProviderResult] = []
        for o in outcomes:
            rows.append(ProviderResult(
                threat_report_id=threat_report_id,
                user_id=user_id,
                provider=o.provider,
                artifact_kind=o.artifact_kind,
                artifact_value=o.artifact_value,
                artifact_hash=sha256_hex(o.artifact_value),
                status=o.status,
                verdict=o.verdict,
                score=o.score,
                normalized_score=o.normalized_score,
                raw=o.raw,
                latency_ms=o.latency_ms,
                http_status=o.http_status,
                error_code=o.error_code,
                error_message=o.error_message,
                expires_at=now_utc(),
            ))
        if not rows:
            return
        try:
            await repo.insert_many(rows)
        except Exception:  # pragma: no cover - persistence must not crash scans
            log.exception("provider_persist_failed", n=len(rows))


provider_aggregation_service = ProviderAggregationService()
