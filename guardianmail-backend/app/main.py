"""GuardianMail FastAPI entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.database.mongodb import mongodb
from app.database.redis import redis_client
from app.database.indexes import ensure_indexes
from app.api.v1 import auth, gmail, emails, phishing, attachments, links, privacy, devices, analytics, reports, ai, dashboard, community

configure_logging()
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


@asynccontextmanager
async def lifespan(_: FastAPI):
    await mongodb.connect()
    await redis_client.connect()
    await ensure_indexes(mongodb.db)
    yield
    await mongodb.close()
    await redis_client.close()


app = FastAPI(
    title="GuardianMail API",
    version="1.0.0",
    docs_url="/docs" if settings.APP_ENV != "prod" else None,
    lifespan=lifespan,
)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestContextMiddleware)

# routers
for r in (auth, gmail, emails, phishing, attachments, links, privacy,
          devices, analytics, reports, ai, dashboard, community):
    app.include_router(r.router, prefix="/api/v1")


@app.get("/healthz", tags=["meta"])
async def healthz():
    return {"status": "ok", "env": settings.APP_ENV}
