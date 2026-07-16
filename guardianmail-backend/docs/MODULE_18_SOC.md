# Module 18 — Enterprise Security Operations Center (SOC)

Additive layer that turns GuardianMail AI into a unified enterprise
security-monitoring platform. It **does not modify** any prior module,
API, model, or business rule — SOC only *consumes* events emitted by
Modules 1–12 and Phases 13–17 and stores its own incidents, cases,
alerts, audit trail, health snapshots, and reports.

---

## 1. Enterprise SOC Architecture

```
 Email ─► Threat Scan ─► Threat Intel ─► OCR ─► AI Analysis
                                   │
                                   ▼
                          Risk Correlation (M17)
                                   │
                    soc_service.ingest_detection()
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              Incident        Alert (if      Audit Log
              (M18)           critical)      Entry
                    │
                    ▼
              SOC Dashboard ─► Investigation ─► Response ─► Reports
```

SOC is **facade-driven**: every subsystem talks to `soc_service` only,
so future modules never grow SOC's blast radius.

---

## 2. SOC Dashboard Design

Aggregated by `DashboardService.build()`; Redis-cached under
`soc:dashboard:v1` for 20 s.

Widgets:
- System Health (mongo/redis/api probes)
- Active Users / Sessions
- Emails Scanned Today · Threats Detected · Critical · High · Safe
- Pending Investigations · Open Complaints · Resolved Incidents
- Background Jobs · Redis · Celery · Mongo · AI / TI provider status
- Severity, type and status breakdowns
- Top domains (24 h) and recent incidents
- Active alerts

`GET /api/v1/soc/dashboard` returns a normalized `DashboardOut`.

---

## 3. Incident Management Architecture

`Incident` fields cover every requirement:
`incident_id, incident_type, threat_category, severity, confidence,
risk_score, user_id, sender, domain, urls, attachments, timeline (join),
evidence, status, assigned_to, resolution`.

Severities: `critical | high | medium | low | informational`.
Score → severity mapping is deterministic (`_severity_from_score`).

---

## 4. Case Management System

`Case` wraps an `Incident` (1:1) with analyst context: owner, priority
(`p1..p4`), notes, comments, attachments, and history.
`POST /api/v1/cases`, `POST /api/v1/cases/{id}/comment`.

---

## 5. Investigation Workflow

State machine enforced by `ALLOWED_TRANSITIONS`:

```
new ─► investigating ─► awaiting_review ─► escalated
              │                │              │
              └────► resolved ◄┴──────────────┘
                        │
                        ▼
                     closed
```

Every transition writes a `IncidentTimelineEntry` and an
`AuditLogEntry`. Illegal transitions raise `ConflictError`.

Timeline mirrors the required lifecycle:
`email_received → gmail_sync → threat_intelligence → ocr →
ai_analysis → threat_score → evidence_pack → complaint_draft →
user_action → resolution`.

---

## 6. Alert Management System

`AlertService.raise_alert(kind, severity, title, message, ...)` with a
bounded `_ALLOWED_KINDS` (critical_threat, ai_failure, redis_failure,
mongo_failure, queue_growth, high_api_latency, provider_failure,
multiple_phishing_emails, repeated_sender, incident_escalated).
Alerts are acknowledged via `POST /api/v1/alerts/{id}/ack`.

---

## 7. System Health Monitoring

`HealthMonitoringService` probes Mongo (`ping`) and Redis (`ping`) and
persists snapshots. `GET /api/v1/system/health` returns the latest per
component, `POST /api/v1/system/health/refresh` forces an immediate
probe. Failures never raise — they record `down`.

---

## 8. Threat Feed Architecture

`GET /api/v1/soc/threat-feed?limit=N` streams incidents in reverse
chronological order with severity, sender, domain, score, confidence,
and status.

---

## 9. Reporting Framework

`ReportService.generate(kind)` produces `daily | weekly | monthly |
adhoc` `SOCReport` documents with severity, type, and status
breakdowns plus top-domain sections. Persisted in `soc_reports`.

---

## 10. Audit Logging Architecture

`AuditService.log(...)` writes to `soc_audit_log` (no soft-delete).
Emitted for every incident/alert/case action. Never raises — audit
failure logs a warning and continues so callers are never blocked.

---

## 11. Search & Filtering Strategy

`IncidentRepository.list_filtered(...)` supports filters:
`severity, status, incident_type, sender, domain, since, user_id` plus
paging. Feed and dashboard queries reuse the same indexed selectors.

---

## 12. Celery Worker Design

`app/workers/soc_tasks.py`:
- `security.soc.snapshot_dashboard`
- `security.soc.snapshot_health`
- `security.soc.generate_report`
- `security.soc.ingest_detection`

Registered on the existing `Q_DEFAULT`/`security.*` routing rule — no
new queues introduced.

---

## 13. Database Design

Collections (all additive):
- `soc_incidents` — main incident store
- `soc_incident_timeline` — append-only per-step timeline
- `soc_cases` — analyst cases (1:1 with incidents)
- `soc_alerts` — active + acknowledged alerts
- `soc_audit_log` — tamper-evident append-only log
- `soc_system_health` — periodic health snapshots
- `soc_reports` — generated report documents

Indexes are inferred from filter fields (`user_id`, `severity`,
`status`, `created_at`, `domain`, `sender`).

---

## 14. API Design

```
GET    /api/v1/soc/dashboard
GET    /api/v1/soc/threat-feed

GET    /api/v1/incidents
POST   /api/v1/incidents
GET    /api/v1/incidents/{id}
PATCH  /api/v1/incidents/{id}
POST   /api/v1/incidents/{id}/assign
GET    /api/v1/incidents/{id}/timeline

POST   /api/v1/cases
GET    /api/v1/cases/{id}
POST   /api/v1/cases/{id}/comment

GET    /api/v1/alerts
POST   /api/v1/alerts/{id}/ack

GET    /api/v1/reports
POST   /api/v1/reports/generate

GET    /api/v1/system/health
POST   /api/v1/system/health/refresh

GET    /api/v1/audit
```

---

## 15. RBAC Architecture

Roles honoured: `user | security_analyst | soc_analyst |
administrator | super_administrator`. Analyst gate: `_require_analyst`.
Non-analysts can only see incidents scoped to their own `user_id`
(via `mine=true` default) and cannot mutate anything.

---

## 16. Logging Strategy

Every write path emits structlog events (`incident_created`,
`incident.transition`, `alert.raised`, `case.opened`,
`case.comment`, `alert.acknowledged`, `soc_ingest_detection_failed`,
`soc_health_snapshot_failed`) plus a mirrored audit-log entry.

---

## 17. Security Strategy

- RBAC-gated endpoints
- Deterministic transition state machine (no arbitrary jumps)
- Alert-kind allowlist prevents unbounded event kinds
- Audit log is append-only (no soft-delete field, no update path)
- Rate-limiting inherited from FastAPI middleware
- Every ingest path is failure-tolerant so SOC never blocks callers

---

## 18. Performance Optimization

- Redis-cached dashboard (20 s TTL) with graceful fallback
- Aggregation-based counts (`$group`) instead of per-row scans
- Bounded page sizes (≤ 100)
- Health probes short-circuit and never raise
- Timeline is a separate collection to keep `soc_incidents` documents
  small and hot in the working set

---

## 19. Testing Strategy

`app/tests/test_phase18_soc.py` covers:
- severity bucket boundaries
- transition-matrix invariants (closed terminal, no jumps to resolved)
- alert-kind allowlist
- dashboard cache-key contract
- graceful missing-alert acknowledgement path

Integration tests reuse the existing Phase 13/14 harness by calling
services through their public functions.

---

## 20. Production Deployment Recommendations

- Schedule `security.soc.snapshot_health` every 60 s and
  `security.soc.snapshot_dashboard` every 20 s via Celery beat
- Schedule `security.soc.generate_report` daily at 00:05 UTC
- Add Prometheus alerts on `soc_alerts{acknowledged=false,severity="critical"}`
- Wire `soc_service.ingest_detection` into the Phase 17 correlation
  pipeline as a fire-and-forget task (already safe: swallows failures)
- Grafana dashboard panels driven from `/api/v1/soc/dashboard`
- Retain `soc_audit_log` for ≥ 1 year (compliance)
