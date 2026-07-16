"""Module 11 — Platform hardening endpoints.

Additive to the existing /healthz|/readyz|/livez under `app.api.health`.
These routes live under `/api/v1/platform/*` and expose structured deep
status, Prometheus metrics, performance snapshots, and rate-limit checks.
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Response, status

from app.core.config import settings
from app.core.response import envelope
from app.services.platform.health_service import HealthService
from app.services.platform.metrics_service import metrics_service
from app.services.platform.performance_service import performance_service

router = APIRouter(prefix="/platform", tags=["platform"])
_health = HealthService()


@router.get("/health")
async def health() -> dict:
    return envelope(await _health.deep_status())


@router.get("/ready")
async def ready() -> dict:
    report = await _health.readiness()
    if report["status"] != "ready":
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=report)
    return envelope(report)


@router.get("/live")
async def live() -> dict:
    return envelope(await _health.liveness())


@router.get("/status")
async def status_() -> dict:
    return envelope({
        "health": await _health.deep_status(),
        "performance": performance_service.snapshot(),
        "env": settings.APP_ENV,
        "version": settings.APP_VERSION,
    })


@router.get("/metrics", include_in_schema=False)
async def metrics(x_metrics_token: str | None = Header(default=None)) -> Response:
    if settings.APP_ENV != "dev":
        if not settings.METRICS_TOKEN or x_metrics_token != settings.METRICS_TOKEN:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid metrics token")
    body, ctype = metrics_service.render()
    return Response(content=body, media_type=ctype)
