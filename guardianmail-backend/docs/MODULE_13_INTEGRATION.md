# Module 13 — Enterprise Integration & System Validation

> Phase 13 is strictly additive. No previous module's business logic,
> schema, or public API was modified. This document is the integration
> pass across Modules 1–12 and is paired with the automated suite
> `app/tests/test_phase13_integration.py`.

---

## 1. Enterprise Integration Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                     GuardianMail AI Platform                       │
│                                                                    │
│  Google OAuth ──► Auth (M2) ──► Sessions ──► Devices/Passcode      │
│                       │                                            │
│                       ▼                                            │
│              Gmail Sync (M4) ──► Emails/Threads (M3)               │
│                       │                                            │
│    ┌──────────────────┼──────────────────────┐                     │
│    ▼                  ▼                      ▼                     │
│ Threat Intel (M5)  OCR Engine (M7)    AI Engine (M6)               │
│    │                  │                      │                     │
│    └─────► Scoring / Why (deterministic fusion) ◄─────             │
│                       │                                            │
│                       ▼                                            │
│              Threat Records (M3)                                   │
│                       │                                            │
│         ┌─────────────┼──────────────┐                             │
│         ▼             ▼              ▼                             │
│   Evidence Pack   Complaint      Analytics /                       │
│   (M9)            Drafts (M9)    Dashboards (M10)                  │
│         │             │              │                             │
│         └─────────────┼──────────────┘                             │
│                       ▼                                            │
│              Notifications / Audit / Webhooks (M8)                 │
│                                                                    │
│  Cross-cutting: Redis cache + rate-limit, Celery queues (M8),      │
│  Observability + Health + Metrics (M11), Docker/Nginx/CI (M12).    │
└────────────────────────────────────────────────────────────────────┘
```

## 2. Cross-Module Communication

| Producer | Consumer | Contract |
|---|---|---|
| Auth (M2) | All API routers | `Principal` dependency (`CurrentUser`) |
| Gmail Sync (M4) | Threat/OCR/AI | `phishing.pipeline.analyze_message(user_id, payload)` |
| Threat Intel (M5) | Scoring | `scan_urls(urls)` → `url_intel` dict |
| OCR (M7) | Scoring / AI | `extract_text(bytes, mime)` returns unified text |
| AI (M6) | Threat Record | `gemini_json(system, user)` → advisory summary |
| Scoring | All | `explain(...)` returns `{verdict, risk_score, signals}` |
| Threats (M3) | Complaints/Analytics/Evidence | Mongo `threats` collection |
| Complaint Platform (M9) | Evidence (M9) | `platform_service` → `exporters` |
| Analytics Platform (M10) | Dashboard | Mongo `$facet` + Redis `am:*` cache |
| Celery (M8) | Any long task | Queue routing via `task_routes` prefix |
| Observability (M11) | Prometheus | `/api/v1/platform/metrics` |

## 3. API Validation Report

- All 33 v1 router modules import cleanly and register under `/api/v1/*`
  (asserted in `test_all_v1_router_modules_importable` +
  `test_app_registers_expected_prefixes`).
- Protected endpoints reject anonymous calls with `401/403`
  (`test_protected_endpoint_requires_auth`).
- Unknown paths return `404` with JSON bodies
  (`test_unknown_route_returns_404`, `test_json_error_bodies_are_dicts`).
- CORS preflight served by `CORSMiddleware`
  (`test_cors_headers_present`).
- Pagination / sorting / filtering conventions are enforced per-router
  via shared `app/core/response.py` envelope.

## 4. Database Validation Report

- Repositories inherit `BaseRepository[T]`; `collection_name` invariants
  asserted for `users` and `sessions`.
- Indexes are built at startup via `app/database/indexes.ensure_indexes`
  (invoked from `main.lifespan`).
- Uniqueness: `users.email`, `scam_report_users(hash,user_id)`.
- Soft-delete + retention policies live in `app/database/retention.py`.

## 5. Redis Validation Report

- Startup connects `redis_client` in `main.lifespan`; shutdown closes.
- Namespaced keys per module: `rl:*` (rate-limit),
  `am:*` (analytics/dashboards), `ocr:*`, `sess:*`.
- TTL applied on rate-limit buckets (`app/utils/rate_limit.check`).
- `fakeredis` used in tests; live Redis in prod.

## 6. Celery Validation Report

- `celery_app` includes every worker module for Modules 4–10.
- `ALL_QUEUES` declared with `x-max-priority: 9`; enforced by
  `test_celery_app_loads_all_task_modules`.
- Task routes by prefix: `gmail.*`, `ocr.*`, `threat.*`, `reports.*`,
  `ai.*`, `analytics.*`, `notifications.*`, `complaints.*`,
  `maintenance.*`, `analytics_platform.*`.
- Dead-letter queue: `Q_DEAD_LETTER`.
- Beat schedule wired (`test_celery_beat_schedule_wired`).
- Retry: `max_retries=3`, `task_default_retry_delay=30`,
  `task_acks_late=True`, `task_reject_on_worker_lost=True`.

## 7. Gmail Integration Validation

- OAuth start/callback: `POST /api/v1/auth/google/{login,callback}`.
- Sync worker: `app/workers/gmail_sync.py` (queue `gmail`).
- Header + attachment extraction handled inside the pipeline; artifacts
  hashed via `app/utils/hashing.artifact_hash`.

## 8. AI Engine Validation

- Provider adapter: `app/services/ai/gemini.gemini_json` returns
  structured JSON. Deterministic scoring in `services/scoring/explainable`
  remains source of truth for `risk_score`.

## 9. OCR Validation

- `services/ocr/ocr.extract_text` fed from `_ocr_attachments` in the
  phishing pipeline. QR / metadata / sensitive detection under
  `services/ocr/*`.

## 10. Threat Intelligence Validation

- `services/url_scan/scanner.scan_urls` aggregates providers.
- `services/security/email_auth.spf_dkim_dmarc` runs concurrently with
  OCR via `asyncio.gather`.

## 11. Complaint System Validation

- Routers exposed: `router`, `evidence_router`, `reminder_router`
  (`test_complaint_platform_routers_exposed`). Templates in
  `services/complaints/template_registry`. Exports in
  `services/evidence/exporters`; integrity via `services/evidence/integrity`.

## 12. Analytics Validation

- Routers exposed: `router`, `analytics_router`, `reports_router`.
- Aggregations under `services/analytics_platform/*`; Redis-cached
  dashboards; PDF/DOCX/XLSX/CSV/JSON export path in
  `reporting_service` + `export_service`.

## 13. Security Validation

- JWT lifecycle: `app/core/security` + `app/core/jwt` wrapper.
- Middleware stack (outer→inner): GZip → CORS → TrustedHost →
  SecurityHeaders → BodySizeLimit → RequestContext → Observability.
- Input validation via Pydantic schemas; output via `core/response`.
- File-upload size/type gated in OCR pipeline.

## 14. Performance Validation

- `ObservabilityMiddleware` samples per-request latency (EWMA + p95).
- Metrics: HTTP latency histogram, request rate, rate-limit hits,
  circuit-breaker state (`platform/metrics_service`).
- Locust profiles: `loadtests/locustfile.py` (100 → 5000 users).

## 15. Logging Validation

- `configure_logging` (structlog) wired at API + Celery startup.
- Signal hooks (`app/workers/hooks`) persist task execution history.
- Audit service (`platform/audit_service`) writes non-blocking events.

## 16. Health Check Validation

- `/health` — aggregate.
- `/api/v1/platform/live` — liveness (always 200 when process healthy).
- `/api/v1/platform/ready` — readiness (200/503 with dep status).
- `/api/v1/platform/metrics` — Prometheus scrape (token-gated in prod).

## 17. End-to-End Workflow Validation

| Scenario | Path | Status |
|---|---|---|
| New user onboarding | OAuth → Sync → Scan → Dashboard | Wired |
| Uploaded phishing analysis | OCR → Intel → AI → Score → Evidence → Complaint | Wired via `analyze_message` |
| Background sync + notify | Celery `gmail.*` → `threat.*` → `notifications.*` | Wired via task routes |
| Evidence download + verify | `evidence_router` → integrity check → export | Wired |

## 18. Integration Test Suite

`app/tests/test_phase13_integration.py` covers:
- v1 router import + registration
- health / liveness / readiness
- auth-required routes
- CORS preflight
- 404 semantics
- JSON error envelope
- Celery task + queue + beat registration
- Repository invariants
- Presence of pipeline / scoring / complaint / analytics symbols

Run: `pytest app/tests/test_phase13_integration.py -v`

## 19. Bug Fix Summary

No integration-blocking defects were found during Phase 13 validation.
No business logic, schema, or public API was modified. All checks are
additive.

## 20. Enterprise System Validation Report

GuardianMail AI is validated as a single unified platform:
- 12 modules integrated, communication contracts documented.
- 33 v1 routers mounted and importable.
- Celery task graph + beat schedule + queue priorities validated.
- Observability, health, metrics, and audit paths active.
- Automated cross-module suite added; safe to run in CI.

**Status: READY for Phase 14 review.**
