# GuardianMail Backend

Event-driven security platform that powers the MailGuard / GuardianMail
frontend. Python 3.11 · FastAPI · MongoDB · Redis · Celery · Docker.

## Why this shape

Most "email security" projects are a REST wrapper around one AI call. This
backend is intentionally different: **every incoming signal is an event**
that fans out to independent, specialised workers. A Gmail sync produces
metadata → metadata produces URLs → URLs trigger threat-intel checks →
attachments trigger OCR + malware analysis → all signals converge into a
single AI-scored verdict with a per-user risk profile.

```text
        ┌─────────────┐    ┌─────────────┐    ┌──────────────┐
Gmail → │ gmail_sync  │ →  │  metadata   │ →  │ url_extract  │
        └─────────────┘    └─────────────┘    └──────┬───────┘
                                                     │
        ┌─────────────┐    ┌─────────────┐    ┌──────▼───────┐
        │   OCR       │ ←  │ attachments │ ←  │ threat_intel │
        └──────┬──────┘    └─────────────┘    └──────┬───────┘
               │                                     │
               └────────────┬────────────────────────┘
                            ▼
                    ┌───────────────┐
                    │  AI verdict   │  (Gemini / vertex / local)
                    └───────┬───────┘
                            ▼
                 MongoDB + Redis + Websocket push
```

## Stack

| Layer            | Tech                                                 |
| ---------------- | ---------------------------------------------------- |
| API              | FastAPI + Pydantic v2 + Uvicorn (Gunicorn in prod)   |
| Auth             | Google OAuth 2.0 + JWT access/refresh + device trust |
| DB               | MongoDB (Motor async) — see `app/database/mongodb.py`|
| Cache / broker   | Redis 7 (aioredis)                                   |
| Async workers    | Celery 5 + Redis broker                              |
| AI               | Google Gemini (vertex + native), pluggable providers |
| OCR              | PaddleOCR → Tesseract fallback                       |
| Threat intel     | VirusTotal · Google Safe Browsing · URLScan · PhishTank · AbuseIPDB · WHOIS/RDAP · SPF/DKIM/DMARC |
| Observability    | structlog + OpenTelemetry-ready                      |
| Reports          | PDF (WeasyPrint), CSV, XLSX (openpyxl)               |
| Container        | Docker + docker-compose (api, mongo, redis, worker, beat, nginx) |

## Layout

```
guardianmail-backend/
├─ app/
│  ├─ api/v1/             # HTTP routers (thin, delegate to services)
│  ├─ core/               # config, security, jwt, encryption, middleware
│  ├─ database/           # mongodb.py, redis.py, indexes.py
│  ├─ models/             # Pydantic models for MongoDB documents
│  ├─ schemas/            # Pydantic request/response schemas
│  ├─ services/           # business logic — one folder per bounded context
│  │  ├─ gmail/  ai/  phishing/  url_scan/  ocr/  reports/  notifications/  security/  automation/
│  ├─ workers/            # celery app + task modules
│  ├─ utils/
│  ├─ tests/
│  └─ main.py             # FastAPI app factory
├─ docker/                # nginx + supervisord configs
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml
└─ README.md
```

## Endpoints (v1)

```text
POST   /api/v1/auth/google              # OAuth exchange
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
GET    /api/v1/auth/me

GET    /api/v1/gmail/sync               # trigger sync (returns Celery task id)
GET    /api/v1/emails                   # list with filters
GET    /api/v1/emails/{id}

POST   /api/v1/phishing/analyze         # full pipeline for a pasted email/msg
POST   /api/v1/url/scan                 # single-URL threat-intel run
POST   /api/v1/ocr                      # image/PDF → text
POST   /api/v1/attachments/scan
POST   /api/v1/reports/export           # PDF/CSV/XLSX
GET    /api/v1/reports/{id}
POST   /api/v1/community/report         # bump community counter for a hash
GET    /api/v1/community/counts

GET    /api/v1/dashboard                # aggregated tiles
GET    /api/v1/analytics                # trend/heatmap data

GET    /api/v1/devices
POST   /api/v1/devices/logout
POST   /api/v1/devices/{id}/trust

GET    /api/v1/privacy/export
POST   /api/v1/privacy/delete
```

## Local dev

```bash
cp .env.example .env         # fill secrets
docker compose up --build    # api on :8000, worker + beat + mongo + redis
```

Run tests:

```bash
docker compose exec api pytest -q
```

## Roadmap (see /docs/ROADMAP.md when you generate it)

- M1  auth + device trust + Gmail OAuth sync
- M2  URL threat-intel fan-out (VirusTotal, GSB, URLScan, PhishTank, WHOIS)
- M3  Attachment OCR + malware profile + AI verdict
- M4  Community reporting + advisories ingest (CERT-In RSS)
- M5  Analytics + weekly PDF report + notifications
- M6  Real-time websocket push + browser extension endpoint
