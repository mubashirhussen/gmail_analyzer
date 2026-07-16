# Module 11 — API Hardening, Performance & Enterprise Readiness

Additive hardening layer on top of Modules 1–10. **No business logic
changes.** Focus: security posture, observability, resilience, and
production-readiness.

---

## 1. API Hardening Architecture

Layered defence in depth, from outermost inbound to innermost:

```
Client → Nginx (TLS, HSTS)
      → GZip → CORS → TrustedHost
      → SecurityHeaders (CSP, XFO, XCTO, Referrer, Permissions)
      → BodySizeLimit (413 on oversize)
      → RequestContext (request-id, structured access log)
      → ObservabilityMiddleware  ← NEW (Prometheus + perf sampler)
      → SlowAPI (in-proc RL)  +  RateLimitService (Redis sliding window)
      → Auth (JWT/OAuth/API-key) → RBAC/Permission guards
      → Route handler → Service → Repository → Mongo/Redis
```

## 2. Middleware Architecture

| Middleware | Purpose | Owner |
| --- | --- | --- |
| `GZipMiddleware` | Compression | FastAPI |
| `CORSMiddleware` | Strict CORS | FastAPI |
| `TrustedHostMiddleware` | Host allow-list | FastAPI |
| `SecurityHeadersMiddleware` | CSP, HSTS, XFO, XCTO | Module 2 |
| `BodySizeLimitMiddleware` | Reject oversize bodies (413) | Module 2 |
| `RequestContextMiddleware` | Request-ID + access log | Module 2 |
| `ObservabilityMiddleware` | Metrics + perf sampler | **Module 11** |

## 3. Authentication & Authorization Flow

Unchanged from Module 2. Module 11 adds:
- `RateLimitService` for per-user, per-IP, per-endpoint policies.
- `AuditService.record(...)` for authn/authz events.

## 4. Request Validation Strategy

- Headers, query, path, body validated via Pydantic v2.
- File uploads validated by MIME + size (Module 7).
- JSON payloads capped by `REQUEST_MAX_BODY_BYTES`.
- Emails/UUIDs validated via Pydantic types (`EmailStr`, `UUID4`).

## 5. Response Standardization

`app/core/response.py` provides `envelope(data, pagination=...)` returning:

```json
{ "data": ..., "meta": { "request_id": "...", "pagination": {...} } }
```

Errors already use the `ErrorEnvelope` from Module 2.

## 6. Rate Limiting Strategy

Two-tier:
1. **SlowAPI** — in-process, per-IP default (fast path).
2. **`RateLimitService`** — Redis sliding-window sorted-set counter with
   per-user / per-IP / per-endpoint policies + burst allowance.
   Fails open on Redis error (metric emitted).

## 7. Performance Optimization Plan

- Connection pools: Motor (`maxPoolSize` env-tunable), Redis (async pool).
- `PerformanceService` samples latency (EWMA + p50/p95/max) in-process.
- `MetricsService` emits Prometheus histograms per method+route.
- Batch writes via existing repositories' bulk helpers.
- `orjson` (already installed by FastAPI stack) for JSON serialization.

## 8. MongoDB Optimization

- Existing `ensure_indexes` block covers hot paths for all modules.
- Slow-query surface via Module 8 `supabase--slow_queries` equivalent — the
  Mongo-side check is exposed through `/platform/status` (deep check).

## 9. Redis Optimization

- Distributed rate limiter uses sorted-set TTL trimmed each request.
- Circuit-breaker state gauge for cache/network dependencies.
- Cache invalidation continues via the module-specific namespaces
  (`am:*`, `ai:*`, `th:*`).

## 10. Async Processing Optimization

- All new services are async / non-blocking.
- `retry_async` provides exponential backoff + jitter for outbound calls.
- `CircuitBreaker` short-circuits misbehaving dependencies.

## 11. Health Check Architecture

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/platform/live` | Liveness — process up |
| `GET /api/v1/platform/ready` | Readiness — deps healthy (503 if not) |
| `GET /api/v1/platform/health` | Deep status (5s cache) |
| `GET /api/v1/platform/status` | Deep status + perf snapshot |
| `GET /api/v1/platform/metrics` | Prometheus exposition (token-gated) |

Legacy `/healthz|/readyz|/livez` remain for existing probes.

## 12. OpenTelemetry Integration

Instrumentation hooks are placed at request boundaries (Observability
middleware) and outbound HTTP client. To enable OTel export, install
`opentelemetry-instrumentation-fastapi` and wire the tracer provider in
`app.core.logging.configure_logging`. All spans inherit the `request_id`
via `contextvars`.

## 13. Prometheus Metrics Design

| Metric | Type | Labels |
| --- | --- | --- |
| `gm_http_requests_total` | Counter | method, route, status |
| `gm_http_request_duration_seconds` | Histogram | method, route |
| `gm_http_exceptions_total` | Counter | route, code |
| `gm_rate_limit_hits_total` | Counter | scope |
| `gm_circuit_state` | Gauge | name |
| Module 8 metrics | (existing) | — |

## 14. Grafana Dashboard Design

Row layout:
1. **Golden Signals** — RPS, error rate, p50/p95/p99 latency.
2. **Availability** — readiness, dependency status heatmap.
3. **Rate Limiting** — rejections by scope.
4. **Circuit Breakers** — state timeline by breaker name.
5. **Workers** (Module 8) — queue depth, task duration.

## 15. Logging Strategy

- `structlog` JSON logs with request-id, user-id, route, status, ms.
- `LoggingService` provides a stable vocabulary for auditing events.
- All exceptions go through `register_exception_handlers` → JSON envelope.

## 16. Fault Tolerance Strategy

- `retry_async` — exponential backoff + jitter.
- `CircuitBreaker` — 3 states (closed / open / half-open).
- Graceful shutdown via FastAPI lifespan closes Mongo/Redis/httpx pools.
- Mongo/Redis auto-reconnect handled by driver defaults.

## 17. Load Testing Strategy

`loadtests/locustfile.py` provides two user classes and profiles for
100 / 500 / 1000 / 5000 concurrent users. Track latency, throughput,
error rate against SLO targets (p95 < 500 ms on hot paths).

## 18. API Documentation Strategy

- OpenAPI generated by FastAPI at `/openapi.json` (non-prod).
- Swagger UI at `/docs`, ReDoc at `/redoc`.
- Response/error examples added via `responses={...}` on new routes.

## 19. Security Audit Checklist

- [x] Dependency scan (weekly CI).
- [x] Secret validation (`settings.validate_secrets`).
- [x] JWT rotation supported (Module 2).
- [x] RBAC enforced (Module 2).
- [x] CSP / HSTS / XFO / XCTO / Referrer / Permissions headers.
- [x] Body size limit.
- [x] Rate limits (in-proc + distributed).
- [x] Audit log for security-sensitive actions.

## 20. Production Readiness Checklist

- [x] Health / readiness / liveness endpoints wired.
- [x] Prometheus metrics exposed (token-gated).
- [x] Structured JSON logging.
- [x] Graceful shutdown (Mongo, Redis, httpx).
- [x] Circuit breakers + retries for outbound calls.
- [x] Load-test scaffold committed.
- [x] Config split (dev / test / staging / prod) via `APP_ENV`.

## 21. Testing Strategy

- Unit tests: services (health, circuit, retry, perf) — `test_platform_hardening.py`.
- Integration tests: existing per-module suites unchanged.
- Load tests: `locustfile.py` with profiles above.
- Chaos: recommend `toxiproxy` in staging to fault-inject Redis/Mongo.

## 22. Enterprise Best Practices

- Least privilege on Mongo/Redis credentials.
- Rotate `METRICS_TOKEN` and JWT signing keys per policy.
- All outbound API calls wrapped in retry + circuit breaker.
- All secrets provided via env; never committed.
- Deploy behind Nginx with TLS 1.2+ and HSTS preload.
