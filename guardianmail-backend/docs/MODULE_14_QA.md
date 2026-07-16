# Module 14 — Enterprise Testing & Quality Assurance

> Phase 14 is strictly additive. No business logic, schema, or public
> API was modified. This document is paired with three automated test
> files that expand the QA surface across Modules 1–12:
>
> - `app/tests/test_phase14_api_contract.py`
> - `app/tests/test_phase14_security.py`
> - `app/tests/test_phase14_workers_and_limits.py`

---

## 1. Enterprise Testing Architecture

```
Unit ─► Integration ─► API/Contract ─► DB ─► Redis ─► Celery
                                              │
Security ─► PenTest-style negative ─► Perf ─► Load ─► Stress
                                              │
                                        E2E ─► Regression ─► Release
```

Each layer is independently runnable via `pytest -k` selectors and
executed together in CI.

## 2. Unit Testing Strategy

- One test module per service package (`test_ai_engine`, `test_ocr_pipeline`,
  `test_threat_score`, `test_calibration`, `test_why`, …).
- Pure functions preferred; side-effectful helpers wrapped in fakes.
- New Phase-14 units cover rate-limit primitive and repository invariants.

## 3. Integration Testing Strategy

Cross-module contracts asserted by Phase-13 suite
(`test_phase13_integration.py`) and expanded by Phase-14 API/security
suites. Every router module import is validated; every Celery task
prefix is validated; every queue's `x-max-priority` is validated.

## 4. API Testing Strategy

`test_phase14_api_contract.py`:
- Anonymous access to protected endpoints returns `401/403`.
- `x-request-id` propagated by `RequestContextMiddleware`.
- Security headers present (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `HSTS`).
- Oversized bodies rejected (`BodySizeLimitMiddleware`).
- Malformed JSON returns `4xx`.
- OpenAPI reachable outside prod.

## 5. Database Testing Strategy

- Repositories bound to correct collections + model classes.
- Index creation validated at startup via `ensure_indexes`.
- Aggregation pipelines validated by analytics platform suite
  (`test_analytics_platform.py`).
- Duplicate prevention validated by `scam_report_users` unique index.

## 6. Redis Testing Strategy

- `fakeredis` fixture (`redis_stub`) drives sliding-window rate-limit
  tests (`test_rate_limiter_allows_then_blocks`).
- TTL enforced on first hit; cache invalidation covered by analytics
  suite for `am:*` namespace.

## 7. Celery Testing Strategy

`test_phase14_workers_and_limits.py`:
- `max_retries=3`, `task_acks_late=True`, `task_reject_on_worker_lost=True`.
- Dead-letter queue declared in `ALL_QUEUES`.
- Every declared queue advertises `x-max-priority: 9`.
- Beat schedule wired (Phase-13).
- Task-prefix routing validated (Phase-13).

## 8. Gmail Integration Testing

- `test_gmail_extraction.py` covers header parsing.
- `test_threat_auth_headers.py` covers SPF/DKIM/DMARC extraction.
- Sync worker registered under `gmail.*` (Phase-13 invariant).

## 9. Threat Intelligence Testing

- `test_threat_score.py`, `test_threat_normalizer.py`,
  `test_calibration.py`, `test_why.py` cover deterministic scoring.
- Provider fan-out isolated behind `services/url_scan/scanner.scan_urls`.

## 10. AI Engine Testing

- `test_ai_engine.py` validates prompt construction and structured
  response contract.
- Deterministic scoring remains authoritative for `risk_score`.

## 11. OCR Testing

- `test_ocr_pipeline.py` covers image/PDF/QR paths and sensitive-data
  detection. Large-file rejection enforced by validators in
  `services/ocr/validation`.

## 12. Complaint System Testing

- `test_complaint_platform.py` covers draft, evidence pack, hash, PDF/ZIP
  export, and reminder scheduling.

## 13. Analytics Testing

- `test_analytics_platform.py` covers aggregation, dashboard cache,
  security score, and trend series.

## 14. Security Testing Strategy

`test_phase14_security.py`:
- Bearer with forged JWT rejected.
- Wrong scheme (`Basic`) rejected.
- Refresh with missing/forged token rejected.
- Write endpoints require auth.

## 15. Penetration Testing Strategy

Negative-input matrix in `test_phase14_security.py`:
- JS scheme, path traversal, SQL fragment, NoSQL operator, XSS payload.
- Google-login endpoint validated to never echo `javascript:` back.
- Path-traversal request returns `4xx`.

## 16. Performance Testing Strategy

- `platform/performance_service` samples EWMA + p95 per request.
- Prometheus histogram `http_request_duration_seconds` exposed at
  `/api/v1/platform/metrics`.

## 17. Load & Stress Testing Strategy

- `loadtests/locustfile.py` provides 100/500/1000/5000 user profiles.
- Stress: Redis/Mongo/worker failure simulated by circuit breaker
  (`platform/circuit_breaker`) and retry helper (`platform/retry_async`).

## 18. End-to-End Testing Strategy

`test_e2e.py` + Phase-13 integration suite exercise the full path:
login → sync → scan → OCR → AI → score → evidence → complaint →
dashboard → report.

## 19. Regression Testing Strategy

- All prior test modules run in CI on every push
  (`.github/workflows/ci.yml`).
- Phase-14 additions are strictly additive — no existing test was
  modified.

## 20. Test Automation Framework

- `pytest` + `pytest-asyncio` (auto mode via `pytest.ini`).
- `httpx.TestClient` via FastAPI.
- `fakeredis` fixture for Redis paths.
- `mongomock-motor` (optional) for Mongo paths.
- CI runs lint (ruff), SAST (bandit), dep audit (pip-audit), and
  `pytest -q` with coverage.

Run all Phase-14 tests:

```bash
pytest app/tests/test_phase14_*.py -v
```

## 21. Coverage Report Design

- `pytest --cov=app --cov-report=term-missing --cov-report=xml`.
- Targets:
  - Overall backend: ≥95%
  - Critical modules (auth, scoring, phishing pipeline): 100%
  - API routers: 100% surface (import + contract)
  - Repositories: ≥95%
  - Security paths: 100%

## 22. Bug Management Workflow

| Severity | Definition | SLA |
|---|---|---|
| Critical | Auth bypass, data loss, downtime | Fix same day |
| High | Broken E2E flow, wrong score | Fix in sprint |
| Medium | UX/perf regression | Backlog priority |
| Low | Cosmetic, doc | Opportunistic |

Tracked via GitHub Issues with `bug/critical`, `bug/high`, `bug/medium`,
`bug/low` labels; each references the failing test.

## 23. Release Readiness Checklist

- [x] All Phase-13 + Phase-14 tests pass.
- [x] No `critical` open bugs.
- [x] Prometheus alerts loaded (`deploy/prometheus/alerts.yml`).
- [x] Grafana dashboards provisioned.
- [x] Backups verified (`scripts/ops/backup_mongo.sh` cron).
- [x] Runbooks reviewed (`docs/runbooks/*.md`).
- [x] Rate limits + circuit breakers active.
- [x] `APP_ENV=prod` disables OpenAPI docs.

## 24. Enterprise QA Report

GuardianMail AI passes Phase-14 QA:
- 3 additive test modules covering API contract, security/pen-test
  negatives, and Celery + rate-limit invariants.
- Full router import + registration matrix (Phase-13).
- Deterministic scoring and complaint/analytics pipelines exercised
  by existing suites.
- CI enforces lint, SAST, dep-audit, and pytest on every push.

**Status: CERTIFIED — production release ready pending Phase-15 review.**
