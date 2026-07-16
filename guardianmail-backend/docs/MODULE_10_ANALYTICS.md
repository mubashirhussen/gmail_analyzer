# Module 10 — Analytics, Security Dashboard & Reporting Platform

Enterprise-grade read/reporting surface that consumes data persisted by
Modules 4-9 and exposes optimized dashboard, analytics, trend, and report
APIs. **Strictly additive** — no code paths in previous modules are
modified.

## 1. Analytics Architecture

```
Gmail metadata ─┐
Threat reports ─┤
AI reports     ─┤   ┌─ AggregationService (Mongo pipelines) ─┐
OCR reports    ─┼─▶ │ AnalyticsService (per-domain assemblers)│ ─┐
Complaints     ─┤   │ TrendService (persisted metric series) │  │
Evidence packs ─┘   └────────────────────────────────────────┘  │
                                                                 ▼
                              ┌───────────────────────────────────────┐
                              │ DashboardService (Redis-cached)       │
                              │ ReportingService (records + gen)      │
                              │ ExportService (pdf/docx/xlsx/csv/json)│
                              └───────────────────────────────────────┘
                                                 ▼
                                         Frontend / Reports
```

## 2. Dashboard Architecture

Single composable entry point: `DashboardService.overview(user_id, tr)`.
It composes KPI cards, ScoreCards (security / trust / threat), email
analytics, security analytics, and a recent-events timeline into
`DashboardOverview`. Scoped reads (`/scope/{name}`) return just one
per-domain payload for lazy-loaded panels.

## 3. Reporting Pipeline

1. `POST /reports-platform/generate` → creates a `report_records` row.
2. Async: Celery task `analytics_platform.generate_report` runs
   `ReportingService.generate_now` → assembles sections →
   `ExportService` serialises → bytes stored in GridFS
   (`report_bytes` bucket) → row updated to `ready` with `download_token`.
3. `GET /reports-platform/download/{token}` streams bytes (24 h TTL).

## 4. MongoDB Aggregation Design

* Every pipeline starts with `{"$match": {"user_id": ..., time_field: ...}}`
  to hit the `(user_id, created_at)` compound index.
* `$facet` used to answer multi-question dashboards in a single round-trip
  (threats overview, email KPI facet).
* `$bucket` used for confidence-distribution histograms.
* `$dateTrunc` on `created_at` shares granularity semantics with
  `TimeFilterService`.

## 5. KPI Framework

`KPIService.card()` is the sole KPI constructor. It computes
`delta_pct` against the prior period and picks a trend arrow honouring
`higher_is_better`. Consumers never assemble KPI cards manually.

## 6. Security Score Calculation

* **security_score** = weighted sum of `safe_ratio` (55), `prevention_rate`
  (25), `1 - recency_penalty` (20). Bands: excellent ≥85, good ≥70,
  fair ≥50, poor ≥30, critical <30.
* **trust_score** = trusted-sender ratio + auth-pass ratio − risky-sender
  penalty + baseline 30.
* **threat_score** = attack pressure (%) + critical boost (×3, cap 30).
  Bands inverted (high pressure ⇒ critical band).

## 7. Dashboard API Design

| Method | Path                                            | Purpose |
| ------ | ----------------------------------------------- | ------- |
| GET    | `/dashboard-platform/overview`                  | Composed KPI + scores + summaries |
| GET    | `/dashboard-platform/scope/{scope}`             | Single per-domain analytics       |
| POST   | `/dashboard-platform/invalidate`                | User-scoped cache flush           |
| GET    | `/analytics-platform/{emails,threats,security,users,domains,ai,ocr,complaints}` | Raw per-domain analytics |
| GET    | `/analytics-platform/trends/{metric}`           | Persisted trend series            |
| POST   | `/analytics-platform/trends/rebuild`            | Kick off trend recompute          |

## 8. Report Generation Architecture

`ReportingService` orchestrates lifecycle transitions
`pending → running → ready | failed | expired`. Section assembly is
kind-aware (`daily`, `weekly`, `monthly`, `security`, `threat`,
`executive`, `email_activity`, `analytics_snapshot`). Sections are then
handed to `ExportService`, which owns format-specific rendering.

## 9. Export Pipeline

* **PDF** — ReportLab (`SimpleDocTemplate`, `Table`).
* **DOCX** — python-docx (`Document`, tables).
* **XLSX** — openpyxl, one sheet per section, bold dark header row.
* **CSV** — `csv.DictWriter` flattened over sections.
* **JSON** — `json.dumps` with `default=str` for datetime.

## 10. Celery Task Architecture

| Task                                     | Schedule            | Queue     |
| ---------------------------------------- | ------------------- | --------- |
| `analytics_platform.daily_rollup`        | 02:15 daily         | analytics |
| `analytics_platform.weekly_rollup`       | Mon 02:30           | analytics |
| `analytics_platform.monthly_rollup`      | Day 1 03:00         | analytics |
| `analytics_platform.warm_dashboard`      | Every 30 min        | analytics |
| `analytics_platform.cleanup_cache`       | 03:45 daily         | analytics |
| `analytics_platform.build_trends`        | On-demand           | analytics |
| `analytics_platform.generate_report`     | On-demand           | analytics |

All tasks are retried on failure (max 3, exponential backoff) and record
their runtime metrics via the existing Module 8 signal hooks.

## 11. Redis Caching Strategy

Namespaced under `am:` (analytics-module). Per-user, per-scope,
per-time-filter keys, TTL 5 minutes for composed dashboards and 2-3
minutes for chart/KPI fragments. Cache hits increment
`dashboard_cache.hits` (best-effort). `DashboardService.invalidate_user`
scans and deletes on write events.

## 12. Database Integration

New collections (all indexed in `app/database/indexes.py`):

* `report_records`      — report lifecycle rows.
* `trend_series`        — persisted per-user metric buckets.
* `dashboard_cache`     — cache-freshness metadata.
* `report_bytes.*`      — GridFS bucket for generated report bytes.

Existing analytics/reports collections and endpoints from previous
modules are left untouched.

## 13. Service Layer

`AnalyticsService`, `TrendService`, `SecurityScoreService`, `KPIService`,
`AggregationService`, `TimeFilterService`, `DashboardService`,
`ReportingService`, `ExportService`. Each has a single responsibility
and no cross-service state.

## 14. Repository Layer

`TrendSeriesRepository`, `ReportRecordsRepository`,
`DashboardCacheRepository` — all extend the shared `BaseRepository`.
The existing `AnalyticsRepository` remains the owner of
`analytics_snapshots`.

## 15. Error Handling Strategy

* Aggregation failures logged with collection + error, caller receives
  an empty list (never a 500 for missing analytics data).
* Cache read/write failures logged and downgraded — the dashboard falls
  back to fresh compute.
* Report generation failures move the record to `status=failed` with the
  error captured for user support.
* Download errors surface as 404 with a stable copy: "report unavailable"
  / "download link expired".

## 16. Logging Strategy

Structured JSON logs via the shared `get_logger`. Notable events:

* `dashboard_computed` (user, scope, compute_ms, filter)
* `report_generated` / `report_generation_failed`
* `slow_query` (from BaseRepository) for >250 ms Mongo ops
* `warm_dashboard_failed`, `daily_rollup_user_failed`

## 17. Testing Strategy

`app/tests/test_analytics_platform.py` covers pure computation:

* Time-filter resolution + previous-period arithmetic.
* KPI delta/trend semantics (both directions).
* Security/threat score bounds and banding.

Integration tests should seed a temporary Mongo, insert sample docs, and
assert on aggregation outputs; that surface stays with the integration
suite so unit tests remain fast.

## 18. Production Deployment Recommendations

* Scale Celery `analytics` queue horizontally — rollups are per-user.
* Configure Redis with maxmemory + LRU eviction (`allkeys-lru`) so
  analytics cache pressure never starves other subsystems.
* Rotate GridFS with a nightly TTL sweep on `report_records.expires_at`;
  add a delete cascade to remove GridFS chunks when reports expire.
* Guard `/dashboard-platform/invalidate` with tighter rate limiting to
  prevent cache-flushing abuse.
* Emit dashboard compute timings to Prometheus via the Module 8 metrics
  registry to spot regressions.
