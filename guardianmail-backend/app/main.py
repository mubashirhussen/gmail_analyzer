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
from app.api.v1 import (admin_review, ai, analytics, attachments, audit, auth,
                        community, complaints, dashboard, devices, emails,
                        evidence, gmail, link_safety, links, notifications,
                        phishing, preferences, privacy, qr, rankings, reports,
                        stream, webhook_deliveries, webhooks)
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

register_exception_handlers(app)

# ---- routers -------------------------------------------------------------
app.include_router(health_router.router)
for r in (auth, gmail, emails, phishing, attachments, links, privacy,
          devices, analytics, reports, ai, dashboard, community, notifications,
          qr, audit, webhooks, webhook_deliveries, rankings, preferences,
          admin_review, stream, link_safety, complaints, evidence):
    app.include_router(r.router, prefix="/api/v1")
