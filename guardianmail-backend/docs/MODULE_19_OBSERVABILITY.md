# Module 19 — Enterprise Observability & Incident Response

Additive observability layer. Does not modify any prior module, API,
model, or business rule. Every subsystem instruments through the
`observability_service` facade so cross-cutting concerns stay decoupled
from the domain.

---

## 1. Enterprise Observability Architecture

```
FastAPI ─► ObservabilityService ─┬─► Prometheus registry (guardian_*)
                                 ├─► OpenTelemetry tracer (OTLP)
                                 ├─► Mongo (obs_spans, obs_alerts,
                                 │           obs_incidents,
                                 │           obs_metric_snapshots)
                                 └─► Structured logs (request_id, trace_id)

AlertManager ──► POST /api/v1/ops/alerts/webhook ──► obs_alerts
Grafana ──► scrape /metrics (existing endpoint, gated by METRICS_TOKEN)
```

---

## 2. OpenTelemetry Integration

`app/core/tracing.py` wires an OTLP HTTP exporter when the SDK is
installed. `OTEL_EXPORTER_OTLP_ENDPOINT` is read at bootstrap.
Without the SDK a no-op tracer is returned so imports never crash.

---

## 3. Distributed Tracing Design

`tracing_service.span("gmail.sync")` and `@tracing_service.traced(...)`
supply spans across the flow: `login → oauth → gmail_sync →
threat_intelligence → ai_analysis → risk_calculation → evidence_pack →
complaint_draft → dashboard`. Each span carries the request id / user id
attributes from `RequestContextMiddleware`.

---

## 4. Metrics Collection Framework

New `guardian_*` series live in
`app/core/observability_metrics.py` and share the existing
`app.core.metrics.REGISTRY`. All record helpers are safe-wrapped in
`MetricsService`.

Catalog:
`guardian_requests_total`, `guardian_request_duration_seconds`,
`guardian_concurrent_requests`, `guardian_login_failures_total`,
`guardian_auth_success_total`, `guardian_scan_duration_seconds`,
`guardian_incidents_total`, `guardian_gmail_sync_total`,
`guardian_ti_provider_latency_seconds`, `guardian_provider_failures_total`,
`guardian_ti_cache_hits_total`, `guardian_ti_cache_misses_total`,
`guardian_ai_latency_seconds`, `guardian_ai_tokens_total`,
`guardian_ai_failures_total`, `guardian_ocr_duration_seconds`,
`guardian_ocr_items_total`, `guardian_queue_depth`,
`guardian_component_up`, `guardian_component_latency_ms`,
`guardian_mongo_ops_total`, `guardian_mongo_slow_queries_total`,
`guardian_redis_hits_total`, `guardian_redis_misses_total`.

---

## 5. Prometheus Configuration

Scrape targets (extend existing `deploy/prometheus/prometheus.yml`):

```yaml
scrape_configs:
  - job_name: guardianmail-api
    metrics_path: /metrics
    scheme: http
    static_configs: [{ targets: ['api:8000'] }]
    authorization:
      credentials_file: /etc/prometheus/metrics-token
```

Recording rules live in `deploy/prometheus/alerts.yml` from Module 12;
add new rules as needed for the metrics above.

---

## 6. Grafana Dashboard Design

Nine boards (one JSON per topic) drawing on `guardian_*` series:

1. Application Overview — RPS, error rate, p50/p95/p99, in-flight
2. Threat Intelligence — provider latency, cache ratio, failures
3. AI Performance — latency, tokens, failure rate, cost estimate
4. Celery — queue depth, task success/failure, retries, DLQ size
5. MongoDB — ops/sec, slow queries, connection pool
6. Redis — hit/miss ratio, memory, evictions
7. Security — incidents by severity, login failures, alert firing
8. Incident Response — open ops incidents, MTTA, MTTR
9. Infrastructure — component-up, latency, resource use

---

## 7. AlertManager Configuration

Suggested rules (extend `deploy/prometheus/alerts.yml`):

```yaml
- alert: APIDown
  expr: guardian_component_up{component="api"} == 0
  for: 1m
  labels: {severity: critical, component: api}
- alert: HighLatencyP95
  expr: histogram_quantile(0.95,
        sum(rate(guardian_request_duration_seconds_bucket[5m])) by (le)) > 1
  for: 10m
- alert: HighErrorRate
  expr: sum(rate(guardian_requests_total{status=~"5.."}[5m]))
      / sum(rate(guardian_requests_total[5m])) > 0.05
  for: 5m
```

AlertManager posts to `/api/v1/ops/alerts/webhook` (network-scoped);
duplicates are folded by fingerprint.

---

## 8. Health Check Architecture

- `/healthz`, `/livez`, `/readyz`, `/version` (existing)
- `/api/v1/system/status` — SRE view, returns per-component probes and
  updates Prometheus gauges as a side-effect
- `/api/v1/system/health/refresh` — Module 18 SOC snapshot

---

## 9. Incident Response Workflow

`OperationalIncident` is opened by SRE tooling or the observability
service and passes through: `open → acknowledged → mitigated →
resolved`. Alerts and incidents are deduped by `kind`. Resolution
records `root_cause` and pushes a timeline entry.

---

## 10. Log Aggregation Strategy

Existing structlog stack unchanged. `RequestContextMiddleware` already
binds `request_id`; when tracing is active, `trace_id` is bound as a
context var so any log line correlates to a span.

---

## 11. Correlation ID Framework

- `request_id` — generated in `RequestContextMiddleware`
- `trace_id` / `span_id` — from OTel
- `session_id`, `incident_id`, `complaint_id`, `evidence_id` — carried
  as span attributes on business calls

---

## 12. Telemetry Database Design

Collections (all additive):
- `obs_spans` — persisted spans for the trace explorer
- `obs_alerts` — AlertManager + internal alerts (deduped by fingerprint)
- `obs_incidents` — operational incidents (distinct from SOC)
- `obs_metric_snapshots` — rolled-up snapshot for fast dashboards

---

## 13. Celery Monitoring Architecture

`app/workers/observability_tasks.py`:
- `security.observability.probe_health` — pings mongo + redis, updates
  `guardian_component_up` / `guardian_component_latency_ms`
- `security.observability.snapshot_metrics` — writes a bounded
  `obs_metric_snapshots` row

Wired under the existing `security.*` routing rule; no new queues.

---

## 14. API Design

```
GET  /api/v1/observability/dashboard
GET  /api/v1/metrics/summary
GET  /api/v1/traces
GET  /api/v1/traces/{trace_id}
GET  /api/v1/system/status
POST /api/v1/ops/alerts/webhook       (AlertManager, unauthenticated)
GET  /api/v1/ops/alerts
POST /api/v1/ops/alerts/{fp}/resolve
GET  /api/v1/ops/incidents
GET  /api/v1/ops/incidents/{id}
POST /api/v1/ops/incidents/{id}/resolve
```

---

## 15. Security Strategy

- RBAC gate `_require_ops` — `admin | super_admin | sre | devops |
  soc_analyst`
- `/metrics` continues to require `METRICS_TOKEN`
- AlertManager webhook is unauthenticated but must be network-scoped
  (private VPC/service mesh) in production
- Audit trail: all mutating endpoints are covered by Phase 18's
  `AuditService`
- Rate-limited by the existing FastAPI slowapi middleware

---

## 16. Performance Optimization

- Metric recording is O(1) and safe-wrapped
- Tracing is sampled at the collector, not the SDK
- Span persistence is bounded (recent-N; explorer only)
- Snapshots feed the dashboard so live pages avoid heavy aggregations
- Redis-cached SOC dashboard (Module 18) remains authoritative for the
  security widgets

---

## 17. Testing Strategy

`app/tests/test_phase19_observability.py` covers:
- fingerprint stability
- no-op tracer safety
- metric safe-wrapping
- alert-service missing-resolve path
- tracing decorator on sync callables

---

## 18. Operational Documentation

- `docs/MODULE_19_OBSERVABILITY.md` — this document
- Metrics catalog above
- Runbooks (Module 12) reference the new dashboards and endpoints
- Alert rules and AlertManager route stubs in
  `deploy/prometheus/alerts.yml` and `deploy/alertmanager/alertmanager.yml`

---

## 19. Production Readiness Checklist

- [x] `guardian_*` metrics exported
- [x] OTel bootstrap (safe when SDK absent)
- [x] Health probes update Prometheus gauges
- [x] AlertManager webhook ingest + dedupe
- [x] Ops incidents with timeline + root cause
- [x] RBAC on all new endpoints
- [x] Celery tasks additive on existing queues
- [ ] Grafana dashboards imported (JSON generation is a deploy-time task)
- [ ] AlertManager routes reviewed with on-call rotation

---

## 20. Enterprise Monitoring Report

Every GuardianMail AI operation is now measurable via `guardian_*`
metrics, traceable via OTel, searchable via `/api/v1/traces`, and
monitorable via `/api/v1/system/status` and
`/api/v1/observability/dashboard`. Alerts flow AlertManager → webhook
→ `obs_alerts`; recurrences fold onto the same fingerprint; ops
incidents auto-dedupe and carry a full timeline. The layer is
non-invasive and remains functional when optional dependencies
(`prometheus_client`, OTel SDK) are absent.
