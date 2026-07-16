# Module 3 — Database Architecture & Repository Layer

Module 3 makes GuardianMail AI's data plane production-ready. It does **not**
add features. It formalises persistence, indexing, caching, and retention
across every collection the platform will touch as later modules ship.

---

## 1. ER-style Overview

```
                          ┌───────────────────┐
                          │      users        │◄─────────────────────┐
                          └─────────┬─────────┘                      │
                                    │ 1                              │
                     ┌──────────────┼──────────────┐                 │
                     ▼              ▼              ▼                 │
              ┌───────────┐   ┌───────────┐  ┌───────────────┐       │
              │ devices   │   │ sessions  │  │  emails       │       │
              └─────┬─────┘   └─────┬─────┘  └───────┬───────┘       │
                    │ 1             │ 1              │ 1             │
                    ▼               ▼                ▼               │
              ┌──────────┐   ┌───────────────┐  ┌────────────┐       │
              │security_ │   │ refresh_tokens│  │  threats   │◄──┐   │
              │ events   │   └───────────────┘  └──────┬─────┘   │   │
              └──────────┘                             │ 1..*    │   │
                                                      ▼         │   │
                                             ┌────────────────┐ │   │
                                             │threat_indicators│ │   │
                                             └────────────────┘ │   │
                                                                │   │
                          ┌────────────┐   ┌──────────────┐     │   │
                          │complaints  ├──►│evidence_packs│─────┘   │
                          └─────┬──────┘   └──────────────┘         │
                                │                                   │
                                ▼                                   │
                         ┌────────────┐     ┌───────────────┐       │
                         │notifications│    │  analytics    │───────┘
                         └────────────┘     └───────────────┘
                         ┌────────────┐     ┌───────────────┐
                         │audit_logs  │     │background_jobs│
                         └────────────┘     └───────────────┘
```

Relationships are **by reference (user_id / threat_report_id / email_id)**;
no cross-collection joins at read time — dashboard reads are served by
`analytics` rollups instead.

## 2. Collections & Ownership

| Collection            | Owner module         | Cardinality       | Notes |
|-----------------------|----------------------|-------------------|-------|
| `users`               | 2 Auth               | 1 per person      | unique(email) |
| `devices`             | 2 Auth               | N per user        | unique(user_id,fingerprint) |
| `sessions`            | 2 Auth               | N per device      | TTL on expires_at |
| `refresh_tokens`      | 2 Auth               | N per session     | TTL on expires_at |
| `login_history`       | 2 Auth               | ~thousands/user   | TTL 180 d |
| `security_events`     | 2 Auth               | N per user        | TTL 365 d |
| `audit_logs`          | 2 Auth               | 1000s/user        | age-cap 365 d |
| `emails`              | 5 Gmail Sync (future)| millions          | metadata only |
| `threats`             | 6 Threat pipeline    | 1 per scan        | soft-delete |
| `threat_indicators`   | 6 Threat pipeline    | N per report      | global de-dup |
| `complaints`          | 9 Complaints         | N per user        | scheduled dispatch |
| `evidence_packs`      | 9 Evidence           | 1..N per report   | TTL on expires_at |
| `notifications`       | 10 Notifications     | 1000s/user        | TTL 30 d |
| `analytics`           | 12 Analytics         | time-bucketed     | immutable |
| `background_jobs`     | 13 Ops               | N per user        | TTL 60 d after finish |

## 3. Schemas
See `app/models/*.py`. Every model extends `Document` and inherits
`_id: str`, `created_at`, `updated_at`, `deleted_at`, `version`.

## 4. Index Strategy
Defined in `app/database/indexes.py`. Highlights:

* **Owner-first compounds** — `(user_id, <sort_key>)` on every list view
  (emails, threats, complaints, notifications, security_events…).
* **Uniqueness** — `email` on users, `gmail_id` on emails,
  `(user_id, fingerprint)` on devices, `jti` on refresh tokens,
  `(destination, category)` on complaint templates.
* **Time queries** — `received_at`, `at`, `created_at`, `scheduled_for`
  indexed DESC to serve "latest N" without in-memory sorts.
* **Hot filters** — `analysis_status`, `status`, `severity`, `read`
  added to compounds so critical dashboards don't scan.
* **TTL** — `sessions.expires_at`, `refresh_tokens.expires_at`,
  `login_history.at (180 d)`, `notifications.created_at (30 d)`,
  `background_jobs.finished_at (60 d)`,
  `security_events.created_at (365 d)`, `evidence_packs.expires_at`.

## 5. Repository Structure
One repository per collection in `app/repositories/`. Each subclass of
`BaseRepository`:

* declares `collection_name`, `model`, `soft_delete`;
* exposes only *database* operations — no external I/O, no cross-repo
  calls, no domain logic;
* returns typed Pydantic models (never raw dicts).

Barrel: `app.repositories.__init__` for DI-friendly imports.

## 6. Base Repository
`app/repositories/base.py`. Surface:

* Reads: `find_by_id`, `get_by_id`, `find_one`, `find_many`, `paginate`,
  `count`, `exists`, `distinct`, `aggregate`.
* Writes: `insert`, `insert_many`, `update`, `update_many`,
  `find_one_and_update`, `replace`.
* Soft delete: `soft_delete_by_id`, `restore_by_id`, hard
  `delete_by_id` / `delete_many` for erasure only.
* Bulk: `bulk_write`.
* Transactions: `async with repo.transaction() as session`.
* Cross-cutting: slow-query logging (>250 ms) with structured context;
  automatic `updated_at`/`version` bumps; duplicate-key → `ConflictError`.

## 7. Pydantic Models
Pydantic v2 (`model_config = ConfigDict(populate_by_name=True)`). Base
`Document` provides UUID `_id`, UTC timestamps, `deleted_at`, `version`,
and `touch()`.

## 8. Validation Strategy
* **Request schemas** live in `app/schemas/*` (public API contract).
* **Response schemas** derive from `ORMModel` (from_attributes) so
  repositories can return internal models without leaking Mongo shape.
* **Internal DTOs** exchanged between services extend `BaseModel`.
* Domain invariants enforced at model construction (e.g. `Complaint.draft_hash`
  required); repositories never re-validate — they trust typed inputs.

## 9. Aggregation Pipelines
Pre-built in the relevant repository:

* `EmailRepository.top_sender_domains` — 30-day sender-domain rollup.
* `ThreatReportRepository.category_breakdown` — count + avg risk per category.
* `ThreatReportRepository.risk_distribution` — `$bucket` risk histogram.
* `ThreatIndicatorRepository.global_frequency` — cross-tenant IOC hotlist.
* `ComplaintRepository.status_counts`, `SecurityEventRepository.severity_counts`.

All pipelines match on `user_id` first (index-friendly) then filter by
time; `allowDiskUse` is opt-in.

## 10. Redis Caching Strategy
`app/database/cache.py`:

* `CacheClient` — JSON get/set with TTL, atomic incr, distributed lock.
* `CacheKeys` — every namespace (user, dashboard, threat score, unread
  notif, session, rate limit). No ad-hoc key strings in callers.
* `CacheTTL` — default TTLs per key type.

Cache invalidation is explicit: repositories that mutate a cached
entity delete the corresponding key in the *service* layer (repositories
stay pure). Distributed locks guard expensive rebuilds (dashboard).

## 11. Data Retention Strategy
`app/database/retention.py` declares `RetentionPolicy` per collection:

* **TTL-backed** (sessions/refresh_tokens/notifications/login_history/
  security_events/background_jobs.finished_at) — Mongo evicts automatically.
* **Soft-delete + purge** (emails, threats, threat_indicators, complaints,
  evidence_packs) — `run_retention()` daily via Celery beat purges
  tombstones older than the grace period.
* **Age-cap** (audit_logs 365 d, login_history 180 d, analytics 730 d,
  background_jobs 30 d).

Windows are configurable per environment via settings; policies are the
single source of truth.

## 12. Query Optimization
* Projection-friendly `find_*` (`projection=` on every read).
* `paginate()` clamps page size (1..200) and always uses an indexed sort.
* Compound indexes match query prefixes (user_id → time → status).
* `Page[T]` returns totals through `count_documents` on the same filter
  — index-covered on all list endpoints.
* Bulk writes for IOC ingestion (`ThreatIndicatorRepository.bulk_upsert`).

## 13. Performance Best Practices
* Motor connection pool sized by env (Module 1).
* Repositories are lightweight — no per-request DB clients; container
  binds one repo instance to the request lifecycle.
* Slow-query threshold configurable via `SLOW_QUERY_MS`; every hit is
  logged with `collection/op/duration_ms/filter`.
* Hot dashboard reads flow through `CacheClient` with 60 s TTL and a
  distributed lock on rebuild — no thundering herd.

## 14. Testing Strategy
Test doubles:

* `mongomock-motor` for repository unit tests (no network).
* `fakeredis` for cache tests (already wired in `tests/conftest.py`).
* `pytest-asyncio` fixtures for per-test isolated DB.

Coverage targets:

* Base repo — pagination boundaries, soft-delete/restore, optimistic
  update, duplicate-key mapping.
* Each repository — CRUD happy path + one domain query (e.g.
  `ComplaintRepository.due_for_dispatch`).
* Aggregations — golden-fixture pipelines with deterministic inputs.
* Load — separate suite hitting Atlas M10 with 1M-doc fixtures.

## 15. Future Scalability Recommendations
* **Sharding key candidates**: `user_id` on `emails`, `threats`,
  `threat_indicators`, `notifications`. All chosen indexes are already
  compatible with a hashed `user_id` shard key.
* **Read replicas** for analytics/reporting queries (`readPreference=secondaryPreferred`
  on those repos).
* **Time-series collections** for `analytics` and `login_history` once
  Atlas cluster is upgraded — same repository surface, backend swap.
* **Change streams** to feed the realtime module (12) without polling.
* **Cold storage tier** — completed `background_jobs` and old
  `audit_logs` archived to S3 via a monthly job; retention policy already
  guards the online window.
