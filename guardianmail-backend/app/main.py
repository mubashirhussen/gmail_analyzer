"""GuardianMail FastAPI entry point.

Wires the middleware stack, exception handlers, lifespan (mongo + redis +
shared httpx client), health/version endpoints, and mounts every v1 router.
Feature modules never touch this file directly except to add their router.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.api import health as health_router
from app.api import metrics as metrics_router
from app.api.v1 import (admin_review, ai, analytics, attachments, audit, auth,
                        community, complaints, dashboard, devices, emails,
                        evidence, gmail, link_safety, links, notifications,
                        ocr, passcode, phishing, preferences, privacy, qr,
                        rankings, reports, sessions, stream, tasks, threats,
                        webhook_deliveries, webhooks)
from app.api.v1 import complaint_platform  # Module 9
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.http import close_client
from app.core.logging import configure_logging, log
from app.core.middleware import (BodySizeLimitMiddleware,
                                 RequestContextMiddleware,
                                 SecurityHeadersMiddleware)
from app.database.indexes import ensure_indexes
from app.database.mongodb import mongodb
from app.database.redis import redis_client


configure_logging()

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("startup", env=settings.APP_ENV, version=settings.APP_VERSION)
    await mongodb.connect()
    await redis_client.connect()
    await ensure_indexes(mongodb.db)
    log.info("startup_complete")
    try:
        yield
    finally:
        log.info("shutdown")
        await close_client()
        await mongodb.close()
        await redis_client.close()
        log.info("shutdown_complete")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url=None if settings.is_prod else "/docs",
    redoc_url=None if settings.is_prod else "/redoc",
    openapi_url=None if settings.is_prod else "/openapi.json",
    lifespan=lifespan,
)
app.state.limiter = limiter

# ---- middleware (outer → inner) ------------------------------------------
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["x-request-id"],
)
if settings.trusted_hosts_list and settings.trusted_hosts_list != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts_list)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.REQUEST_MAX_BODY_BYTES)
app.add_middleware(RequestContextMiddleware)
# Module 11 — observability (Prometheus + perf sampler). Inner so it wraps
# the actual handler and captures the final status code.
from app.middlewares.observability import ObservabilityMiddleware  # noqa: E402
app.add_middleware(ObservabilityMiddleware)

register_exception_handlers(app)

# ---- routers -------------------------------------------------------------
app.include_router(health_router.router)
app.include_router(metrics_router.router)
for r in (auth, sessions, devices, passcode,
          gmail, emails, phishing, attachments, links, privacy,
          analytics, reports, ai, dashboard, community, notifications,
          qr, audit, webhooks, webhook_deliveries, rankings, preferences,
          admin_review, stream, link_safety, complaints, evidence, threats,
          ocr, tasks):
    app.include_router(r.router, prefix="/api/v1")

# Module 9 — complaint & evidence platform (additive routers).
app.include_router(complaint_platform.router, prefix="/api/v1")
app.include_router(complaint_platform.evidence_router, prefix="/api/v1")
app.include_router(complaint_platform.reminder_router, prefix="/api/v1")

# Module 10 — analytics, dashboard, and reporting platform.
from app.api.v1 import analytics_platform  # noqa: E402
app.include_router(analytics_platform.router, prefix="/api/v1")
app.include_router(analytics_platform.analytics_router, prefix="/api/v1")
app.include_router(analytics_platform.reports_router, prefix="/api/v1")

# Module 11 — platform hardening endpoints (/api/v1/platform/*).
from app.api.v1 import platform as platform_router  # noqa: E402
app.include_router(platform_router.router, prefix="/api/v1")

# Phase 16 — Explainable AI Security Copilot (/api/v1/copilot/*).
from app.api.v1 import copilot as copilot_router  # noqa: E402
app.include_router(copilot_router.router, prefix="/api/v1")

# Phase 17 — Advanced Threat & Fraud Detection (/api/v1/detection/*).
from app.api.v1 import detection as detection_router  # noqa: E402
app.include_router(detection_router.router, prefix="/api/v1")
app.include_router(detection_router.risk_router, prefix="/api/v1")
app.include_router(detection_router.fraud_router, prefix="/api/v1")

# Phase 18 — Enterprise SOC (/api/v1/soc/*, /incidents, /alerts, ...).
from app.api.v1 import soc as soc_router  # noqa: E402
app.include_router(soc_router.router, prefix="/api/v1")
app.include_router(soc_router.incidents_router, prefix="/api/v1")
app.include_router(soc_router.cases_router, prefix="/api/v1")
app.include_router(soc_router.alerts_router, prefix="/api/v1")
app.include_router(soc_router.reports_router, prefix="/api/v1")
app.include_router(soc_router.system_router, prefix="/api/v1")
app.include_router(soc_router.audit_router, prefix="/api/v1")

# Phase 19 — Observability & Incident Response (/api/v1/observability/*, /traces, /ops/*).
from app.api.v1 import observability as obs_router  # noqa: E402
from app.core.tracing import configure_tracing  # noqa: E402
configure_tracing(service_name=settings.APP_NAME)
app.include_router(obs_router.router, prefix="/api/v1")
app.include_router(obs_router.metrics_router, prefix="/api/v1")
app.include_router(obs_router.traces_router, prefix="/api/v1")
app.include_router(obs_router.system_router, prefix="/api/v1")
app.include_router(obs_router.ops_alerts_router, prefix="/api/v1")
app.include_router(obs_router.ops_incidents_router, prefix="/api/v1")
