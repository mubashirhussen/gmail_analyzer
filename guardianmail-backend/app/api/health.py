"""Health / readiness / liveness / version endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, status

from app.core.config import settings
from app.database.mongodb import mongodb
from app.database.redis import redis_client

router = APIRouter(tags=["meta"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "env": settings.APP_ENV}


@router.get("/livez")
async def livez() -> dict:
    return {"status": "alive"}


@router.get("/readyz")
async def readyz() -> dict:
    mongo_ok = await mongodb.ping()
    redis_ok = await redis_client.ping()
    ok = mongo_ok and redis_ok
    payload = {"status": "ready" if ok else "degraded",
               "mongo": mongo_ok, "redis": redis_ok}
    if not ok:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=payload)
    return payload


@router.get("/version")
async def version() -> dict:
    return {"name": settings.APP_NAME, "version": settings.APP_VERSION,
            "env": settings.APP_ENV}


@router.get("/metrics")
async def metrics(x_metrics_token: str | None = Header(default=None)) -> dict:
    if settings.APP_ENV != "dev":
        if not settings.METRICS_TOKEN or x_metrics_token != settings.METRICS_TOKEN:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid metrics token")
    # Prometheus exposition wiring lives in module 13 (Ops).
    return {"status": "ok"}
