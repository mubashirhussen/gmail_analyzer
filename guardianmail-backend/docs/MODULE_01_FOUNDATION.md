# GuardianMail AI — Module 1: Project Foundation

Module 1 delivers only the backend foundation. **No business logic, no
authentication, no Gmail, no AI, no threat pipeline** — those land in
later modules. Everything below is intentionally reusable, framework-
level plumbing that every future module will consume.

## 1. Folder Structure

```
guardianmail-backend/
├── app/
│   ├── api/                    # HTTP layer (routers only, no logic)
│   │   ├── health.py           # /healthz /livez /readyz /version /metrics
│   │   └── v1/                 # versioned business routers (existing)
│   ├── core/                   # cross-cutting framework code
│   │   ├── config.py           # typed settings, prod guardrails
│   │   ├── container.py        # AppContainer (lazy DI singletons)
│   │   ├── context.py          # contextvars request context
│   │   ├── clock.py            # single time source
│   │   ├── ids.py              # request/uuid/token generators
│   │   ├── http.py             # shared pooled httpx.AsyncClient
│   │   ├── logging.py          # structlog + rotation + redaction
│   │   ├── middleware.py       # request ctx, security headers, body limit
│   │   ├── errors.py           # ErrorEnvelope / ErrorResponse schemas
│   │   ├── exceptions.py       # DomainError hierarchy + handlers
│   │   └── security.py         # jwt, passlib, hashing (foundation only)
│   ├── database/
│   │   ├── mongodb.py          # Motor client + pool + ping
│   │   ├── redis.py            # aioredis client + ping
│   │   └── indexes.py          # collection index bootstrap
│   ├── repositories/
│   │   └── base.py             # generic BaseRepository[T]
│   ├── services/
│   │   └── base.py             # BaseService with bound logger
│   ├── models/
│   │   └── base.py             # Document base (id, created/updated_at)
│   ├── schemas/
│   │   └── base.py             # PageParams, Page[T], OKResponse
│   ├── middlewares/            # thin re-export layer for clarity
│   ├── utils/                  # pure helpers (hashing, rate-limit, ...)
│   ├── workers/
│   │   ├── celery_app.py       # Celery factory (broker/backend/retries)
│   │   └── scheduler.py        # beat schedule registry
│   ├── tests/
│   │   ├── conftest.py         # settings override + client + redis stub
│   │   ├── test_config.py
│   │   ├── test_meta.py
│   │   └── test_health.py
│   └── main.py                 # FastAPI factory + lifespan + router mount
├── docker/                     # nginx + supervisord configs
├── docs/                       # architecture & module notes
├── scripts/                    # ops helpers (wait-for.sh, ...)
├── logs/                       # rotated file logs (when LOG_TO_FILE=1)
├── Dockerfile                  # multi-stage, non-root, tini, healthcheck
├── docker-compose.yml          # dev: api + worker + beat + mongo + redis
├── docker-compose.prod.yml     # prod: gunicorn + nginx overrides
├── pytest.ini
├── requirements.txt
└── .env.example
```

## 2. Folder Purpose

| Folder            | Purpose                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `api/`            | Thin HTTP handlers. **No business logic.** Delegate to services.        |
| `core/`           | Framework-level primitives (config, logging, DI, errors, security).     |
| `database/`       | Connection managers only. Queries live in repositories.                 |
| `repositories/`   | Data access. One class per collection. Extends `BaseRepository`.        |
| `services/`       | Business orchestration. Composes repositories + external adapters.      |
| `models/`         | Persisted MongoDB documents (Pydantic).                                 |
| `schemas/`        | Request / response DTOs. Never persisted directly.                      |
| `middlewares/`    | ASGI middleware surface (context, headers, gzip, body limit).           |
| `workers/`        | Celery app + tasks. Business tasks arrive in later modules.             |
| `utils/`          | Pure functions. No I/O.                                                 |
| `docker/`         | Nginx / supervisord.                                                    |
| `scripts/`        | Ops helpers (wait-for, migrations bootstrap, seed).                     |
| `logs/`           | Rotated file logs (opt-in via `LOG_TO_FILE=1`).                         |
| `tests/`          | Pytest suite. `conftest.py` provides shared fixtures.                   |
| `docs/`           | Architecture notes + per-module design docs.                            |

## 3. Configuration Flow

```
os.environ / .env
      │
      ▼
Settings (pydantic-settings, validated at boot)
      │
      ├─ prod guardrails: SECRET_KEY≥32, FERNET_KEY≥32,
      │  no wildcard CORS/hosts, METRICS_TOKEN required
      │
      ▼
settings (lru_cache singleton) ← imported by every layer
```

## 4. Dependency Flow

```
Route (api/*)
   │  Depends(...)
   ▼
Service (services/*)
   │
   ▼
Repository (repositories/*)
   │
   ▼
Motor / Redis / httpx
```

Container (`app.core.container.AppContainer`) holds lazy singletons for
adapters that outlive a request (e.g. AI client, threat-intel client)
once feature modules register them.

## 5. Database Architecture

- **Client:** single `AsyncIOMotorClient` created in the lifespan
  startup hook with pool sizing, timeouts, `retryWrites`, and `appname`.
- **Access:** `get_db()` — never touch the client directly.
- **Repos:** `BaseRepository[T]` covers CRUD; per-collection repos add
  domain queries.
- **Indexes:** `ensure_indexes(db)` runs at startup and is idempotent.
- **Health:** `mongodb.ping()` powers `/readyz`.

## 6. Redis Architecture

- Single `aioredis` client with `max_connections`, `decode_responses`,
  and periodic health checks.
- Uses: cache, rate-limit buckets, Celery broker/backend, pub/sub for
  the future SSE stream.
- Health: `redis_client.ping()` powers `/readyz`.

## 7. Celery Architecture

- Broker + backend = Redis (URLs overridable).
- Queues: `default`, `ocr`, `threat`, `report`.
- `task_acks_late=True`, `task_reject_on_worker_lost=True`,
  `worker_prefetch_multiplier=1` → safe redelivery.
- `broker_connection_retry_on_startup=True` for cold-boot resilience.
- Logging piped through the same structlog config as the API.

## 8. Logging Architecture

- `structlog` on top of stdlib.
- Auto-binds `request_id`, `user_id`, `device_id`, `path`, `method`
  from `app.core.context`.
- JSON in prod/staging; colored k=v in dev (`LOG_JSON=false`).
- Redacts obvious secrets (`authorization`, `token`, `password`,
  `refresh_token`, `client_secret`, ...).
- Rotates to `logs/app.log` (10 MB × 5) when `LOG_TO_FILE=1`.

## 9. Security Architecture

- JWT (HS256 default) via `create_access_token` / `create_refresh_token`.
- Passwords hashed with `passlib[bcrypt]`.
- AES-GCM helper (`app/core/encryption.py`, kept) for at-rest secrets.
- Rate limiting via `slowapi` (`RATE_LIMIT_DEFAULT=120/minute`).
- Security headers middleware: HSTS/CSP in prod, `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`.
- Body-size limit middleware (default 2 MiB) rejects oversize payloads
  before the handler runs.
- TrustedHost middleware active when `TRUSTED_HOSTS` is not `*`.
- `/metrics` requires `x-metrics-token` outside dev.

## 10. Middleware Architecture (outer → inner)

```
Client
  → GZipMiddleware
  → CORSMiddleware
  → TrustedHostMiddleware        (when TRUSTED_HOSTS ≠ *)
  → SecurityHeadersMiddleware
  → BodySizeLimitMiddleware
  → RequestContextMiddleware     (assigns request_id, binds ctx, access log)
  → route handler
```

## 11. Error Handling Flow

```
raise DomainError(...)                  ┐
raise ValidationError / AuthError / ... │
raise ExternalServiceError / ...        ├─► register_exception_handlers
FastAPI RequestValidationError          │      → ErrorResponse envelope
Starlette HTTPException                 │      → JSON, correct status
Unhandled Exception                     ┘      → 500 + logged w/ stack
```

Every response body is `{"error": {"code","message","details","request_id"}}`.

## 12. Docker Architecture

- **Base image:** `python:3.12-slim`.
- **Multi-stage** (`base` → `runtime`) with non-root `app` user and
  `tini` as PID 1.
- `HEALTHCHECK` hits `/healthz`.
- **Dev compose:** hot-reload uvicorn + mounted source, Mongo + Redis
  + worker + beat + flower.
- **Prod compose overlay** (`docker-compose.prod.yml`): `gunicorn -k
  uvicorn.workers.UvicornWorker`, Nginx reverse proxy, no source mount.

## 13. Startup Sequence

```
1. configure_logging()               # structlog wired
2. Settings() validated              # fail-fast in prod
3. FastAPI(app) constructed
4. middleware chain registered       # outer → inner (see §10)
5. exception handlers registered
6. routers mounted (/healthz + /api/v1/*)
7. lifespan.enter:
     mongodb.connect() + ping
     redis_client.connect() + ping
     ensure_indexes(db)
8. server accepts traffic
9. lifespan.exit (SIGTERM):
     close_client() (httpx)
     mongodb.close()
     redis_client.close()
```

## 14. Best Practices Applied

- SOLID, DRY, KISS — one job per file, no God modules.
- Async I/O end-to-end (Motor, aioredis, httpx).
- Pydantic v2 everywhere; typed settings; no `os.environ` scattered.
- Single clock (`core.clock.now_utc`), single id source (`core.ids`).
- 12-factor config, immutable images, graceful shutdown.
- No global mutable state outside connection managers + container.
- Structured logging with per-request correlation.
- Fail-closed defaults (prod guardrails, 2 MiB body cap, deny-by-default CSP).

## 15. Future Integration Points

| Future module              | Hook it will use                                             |
| -------------------------- | ------------------------------------------------------------ |
| Auth & Session (M4)        | `core.security` JWT helpers, `middleware` ctx, audit repo    |
| Gmail Sync (M5)            | `core.http` client, Celery `default` queue, encryption util  |
| Threat Pipeline (M6/M7)    | Celery `threat`/`ocr` queues, `container` for adapters       |
| Scoring / Explainability   | `services.base` + `repositories.base`                        |
| Notifications / Webhooks   | Redis pub/sub, `webhook_deliveries` repo, `container`        |
| Realtime SSE (M11)         | Redis pub/sub + `RequestContextMiddleware` request id        |
| Reports & Analytics (M12)  | Celery `report` queue + beat schedule                        |
| Ops / Metrics (M13)        | `/metrics` endpoint (token-guarded), OTEL wrappers           |

Module 1 is now the stable substrate. Approve to proceed to **Module 2
— Persistence Layer** (base repositories per collection, transactions,
migration scripts, retention/TTL policies).
