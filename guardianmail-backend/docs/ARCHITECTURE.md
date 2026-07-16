# GuardianMail AI — Architecture Summary (Modules 1–12)

## The stack, top to bottom
```
                      Users / Analysts
                            │
                    HTTPS (Nginx TLS)      ── Module 12
                            │
             ┌──────────────▼──────────────┐
             │ FastAPI (Gunicorn+Uvicorn)  │ Modules 1, 2, 11, 12
             │ ─ AuthN/AuthZ, RBAC          │
             │ ─ Middleware: CTX, Sec, RL   │
             │ ─ Observability (Prom, perf) │
             └──────┬───────────────┬──────┘
                    │               │
                    ▼               ▼
         ┌────────────────┐  ┌──────────────┐
         │ Redis          │  │ Celery       │  Module 8
         │ ─ cache        │  │ queues:      │
         │ ─ RL           │  │  gmail, threat,
         │ ─ broker       │  │  ai, ocr,    │
         │ ─ Streams DLQ  │  │  analytics,  │
         └───────┬────────┘  │  complaints… │
                 │           └──────┬───────┘
                 ▼                  ▼
             ┌───────────────────────────┐
             │ MongoDB (Atlas)           │  Module 3
             │ Emails, Threats, AI, OCR, │
             │ Complaints, Analytics,    │
             │ Reports, Audit, BgJobs    │
             └───────────────────────────┘
```

## Module map

| # | Module | Purpose | Key surface |
| - | ------ | ------- | ----------- |
| 1 | Project Foundation | FastAPI skeleton, config, logging, DI | `app/main.py`, `app/core/*` |
| 2 | AuthN & Security | JWT, sessions, RBAC, security headers | `api/v1/auth`, `core/middleware` |
| 3 | DB & Repositories | Motor, Mongo indexes, repo pattern | `app/database`, `app/repositories` |
| 4 | Gmail Integration | OAuth, sync, message model | `services/gmail`, `workers/gmail_tasks` |
| 5 | Threat Intelligence | VT, GSB, urlscan, RDAP, scoring | `services/threat` |
| 6 | AI Analysis Engine | LLM reasoning, explainable report | `services/ai` |
| 7 | OCR & Attachment | Tesseract, QR, sensitive-data | `services/ocr` |
| 8 | Background Platform | Celery, DLQ, dispatcher, metrics | `services/tasks`, `workers/hooks` |
| 9 | Complaints & Evidence | Signed evidence packs, drafts | `services/complaints`, `services/evidence` |
| 10 | Analytics & Reports | Dashboards, KPIs, exports | `services/analytics_platform` |
| 11 | API Hardening | RL, circuit, retry, health, metrics | `services/platform`, `api/v1/platform` |
| 12 | DevOps & Cloud | Docker, CI/CD, Terraform, monitoring | `deploy/`, `terraform/`, `.github/workflows/` |

## Data flow — a phishing email end-to-end

1. **Gmail sync** (M4) pulls a new message → stored in `emails`.
2. **Task dispatcher** (M8) enqueues `threat.scan_email` on the `threat` queue.
3. **Threat Engine** (M5) runs URL/domain/IP/attachment analysis with
   `retry_async` + `CircuitBreaker` (M11), writes `threat_reports`.
4. **AI Engine** (M6) consumes the threat report, calls Lovable AI Gateway
   through `llm_client`, writes `ai_reports`.
5. **OCR** (M7) processes attachments, feeds indicators back into M5/M6.
6. **Analytics** (M10) rolls all of the above into `trend_series` +
   dashboard cache (Redis).
7. **Complaints** (M9) generates signed evidence pack on demand.
8. Every step is measured via **Prometheus** (M11) and shipped via
   **Docker → CloudWatch** (M12).

## Operational envelope

- SLO targets: p95 <500 ms on hot API paths, 99.9% availability.
- Backup: daily Mongo + 6h Redis to S3 (SSE + lifecycle).
- DR: RTO 60 min, RPO 24 h.
- CI/CD: PR gates (lint, SAST, deps, tests) → GHCR (Trivy) → manual deploy → smoke.
- Observability: metrics (Prometheus/Grafana), traces (OTel-ready), JSON logs (CloudWatch), audit (Mongo).

The platform is now feature-complete, hardened, and production-deployable.
Awaiting your approval before proceeding to Module 13.
