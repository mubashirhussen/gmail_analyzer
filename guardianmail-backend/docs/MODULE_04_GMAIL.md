# Module 4 — Gmail Integration & Email Synchronization

Metadata-first Gmail ingestion pipeline. Connects a user's Gmail account
through the platform's OAuth flow (Module 2), synchronises message
metadata, extracts security-relevant indicators (headers, URLs,
attachment metadata), and hands off to the downstream threat analyzer.
No message bodies are persisted by default — the `full_body_retained`
flag is only set for messages explicitly submitted for a forwarded scan.

---

## 1. Gmail Integration Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                            API Layer (FastAPI)                         │
│                                                                        │
│  /api/v1/gmail/*  ─── connect, disconnect, reconnect, status,          │
│                       sync, sync/history, health, threads, labels      │
│  /api/v1/emails/* ─── list, detail, thread                             │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              Service Layer                             │
│                                                                        │
│  GmailAuthService  ──► OAuthService (Module 2) + AES-GCM encryption    │
│  GmailSyncService  ──► orchestrates initial + history.list runs        │
│  EmailMetadataService                                                  │
│  HeaderParserService                                                   │
│  UrlExtractionService                                                  │
│  AttachmentMetadataService                                             │
│  ThreadService                                                         │
│  LabelService                                                          │
│  SyncMonitoringService                                                 │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                            Repository Layer                            │
│                                                                        │
│  GmailConnectionsRepository, EmailRepository, EmailThreadsRepository,  │
│  EmailLabelsRepository, SyncLogsRepository                             │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  MongoDB: gmail_connections, emails, email_threads, email_labels,      │
│           sync_logs                                                    │
│  Redis  : per-user sync lock (`lock:gmail:sync:{user_id}`),            │
│           OAuth state (reused from Module 2)                           │
│  Celery : gmail.sync_all (beat), gmail.sync_user, gmail.sync_labels    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Gmail OAuth Flow

1. Client `POST /api/v1/gmail/connect` → `GmailAuthService.build_connect_url`
   reuses `OAuthService.build_authorize_url` (server-minted CSRF `state`
   stored in Redis with TTL).
2. User consents at Google → redirected to app callback with `code + state`.
3. Client `POST /api/v1/gmail/connect/callback` → the service:
   - consumes `state` (single-use),
   - exchanges `code` for tokens,
   - **validates the granted scope set** against `REQUIRED_SCOPES`
     (`gmail.readonly`, `gmail.modify`, `userinfo.email`, `openid`),
   - refuses if `refresh_token` is missing (Google elides it on prior consent),
   - AES-GCM-encrypts the refresh token, upserts a `GmailConnection` row.
4. An initial-import + label-sync Celery task is fanned out.

Refresh tokens are decrypted only inside the process that talks to Google
and never leave the service boundary.

---

## 3. Email Synchronization Flow

Effective sync mode is chosen automatically:

| Caller intent | Cursor present? | Effective mode |
|---------------|-----------------|----------------|
| `initial`     | any             | initial full   |
| `incremental` | yes             | history.list   |
| `incremental` | no              | initial full   |
| `manual`      | present → history, else initial               |
| `scheduled`   | same as `manual`                              |
| `resume`      | initial full (used after history 404)         |

- **Initial import** pages through `users.messages.list?q=newer_than:30d`
  (100/page) and pulls each new message with `format=metadata` and a
  curated `metadataHeaders` list.
- **Incremental** pages through `users.history.list?startHistoryId=<cursor>`,
  applying `messagesAdded`, `messagesDeleted`, `labelsAdded`,
  `labelsRemoved`. A 404 → history_id expired → falls back to initial.
- **Duplicate detection**: `emails` collection has a unique sparse index on
  `gmail_id`; upsert returns whether the doc was newly inserted. New
  gmail_ids are queued to `threat.analyze_gmail_message`.
- **Single-flight**: `SET lock:gmail:sync:{user_id} EX 1800 NX` prevents
  concurrent runs for the same user.
- **Rate limit / quota**: HTTP 429/5xx retried with exponential backoff +
  jitter; sustained 429 raises `GmailQuotaExceeded` → connection is
  marked `quota_paused` and the sync log status is `partial`.
- **Reauth**: refresh failure raises `GmailReauthRequired` → connection
  status is `reauth_required` and the UI prompts the user to reconnect.

---

## 4. Metadata Extraction Flow

`EmailMetadataService.build()` assembles an `EmailDoc` from a raw Gmail
message payload. Delegates to:

- `HeaderParserService` — extracts Message-ID, Return-Path, Reply-To,
  Received chain, `Authentication-Results` (SPF/DKIM/DMARC verdicts),
  X-Originating-IP, User-Agent/Mailer, Content-Type, List-Unsubscribe.
- `UrlExtractionService` — regex over text + HTML parser over anchors,
  images, and form actions. Normalises scheme + host case, strips
  trailing punctuation, dedupes by canonical form, records source
  (`text` / `html` / `button` / `image`).
- `AttachmentMetadataService` — recursively walks MIME parts, extracting
  filename, extension, MIME type, size, and Gmail `attachmentId`.
  **Contents are never persisted here.**

Body-storage policy: `keep_body=False` by default; only the forwarded/deep
scan path passes `keep_body=True` and sets `full_body_retained=True`.

---

## 5. Header Parsing Flow

`Authentication-Results` is parsed with `(spf|dkim|dmarc)\s*=\s*<verdict>`
so any ordering, whitespace, or vendor-specific noise is tolerated. Only
the first `Received` 20 hops are kept (bounded write size).

## 6. URL Extraction Flow

- Regex `https?://[^\s<>"'()\[\]{}]+` over plain text, capped at 500 hits.
- HTMLParser collects `<a href>`, `<img src>`, `<form action>`; capped at
  500. Fallback regex over raw HTML catches malformed attributes.
- Normalisation: lowercase scheme + host, strip trailing punctuation,
  preserve path/query, drop fragments, compute apex domain + subdomain,
  dedupe by normalized URL.

## 7. Attachment Metadata Flow

Recursive walk over `payload.parts`. Any part with an `attachmentId` or a
non-empty `filename` produces an `AttachmentMeta` (extension derived from
the filename if MIME is missing). SHA-256 is filled by the OCR/scan
pipeline when it actually fetches bytes.

---

## 8. Database Integration

New collections (all indexes defined in `app/database/indexes.py`):

| Collection          | Purpose                              | Key indexes |
|---------------------|--------------------------------------|-------------|
| `gmail_connections` | one row per (user, gmail_account)    | `(user_id, email)` unique, `(user_id, status)`, `google_sub` sparse |
| `email_threads`     | conversation rollup                  | `(user_id, thread_id)` unique, `(user_id, last_message_at DESC)`   |
| `email_labels`      | mirrored Gmail labels                | `(user_id, label_id)` unique, `(user_id, type, name)`              |
| `sync_logs`         | per-run audit                        | `(user_id, started_at DESC)`, `started_at` TTL=90d                 |

`emails` gains `(user_id, connection_id, received_at DESC)` and a sparse
`(user_id, history_id)` index used by history.list back-references.

Repositories are strictly persistence — no OAuth or Gmail I/O.

---

## 9. Service Layer Design

Every service has one responsibility (see file docstrings). Cross-service
composition happens only inside `GmailSyncService`, which is the sole
place that:

- talks to Google,
- writes to more than one collection,
- fans out downstream Celery tasks.

Services expose module-level singletons (`gmail_sync_service`,
`gmail_auth_service`, …) so route handlers stay thin.

---

## 10. Repository Integration

Only repositories touch Motor. Services obtain them via
`Repo(get_db())` — no injection framework required for stateless
repositories. Transactions are exposed on `BaseRepository.transaction()`
but Gmail sync is idempotent by `gmail_id`, so cross-collection updates
inside `_persist_message` do not require them.

---

## 11. Celery Task Architecture

| Task name             | Queue    | Retries | Purpose                             |
|-----------------------|----------|---------|-------------------------------------|
| `gmail.sync_all`      | default  | —       | beat: enumerate + fan out per-user  |
| `gmail.sync_user`     | default  | 3 × 60s | one user's sync (any kind)          |
| `gmail.sync_labels`   | default  | 2 × 120s| refresh Gmail label catalogue       |
| `threat.analyze_gmail_message` | threat | (downstream module) | per-message analysis |

Beat cadence: `gmail.sync_all` every 15 min (defined in `scheduler.py`).

---

## 12. Redis Usage

| Key                              | TTL     | Purpose                        |
|----------------------------------|---------|--------------------------------|
| `lock:gmail:sync:{user_id}`      | 1800 s  | single-flight per-user sync    |
| `oauth:state:{state}` (Module 2) | 600 s   | OAuth CSRF state (reused)      |

---

## 13. API Endpoints (v1)

| Method | Path                            | Purpose                              |
|--------|---------------------------------|--------------------------------------|
| POST   | `/gmail/connect`                | start OAuth (returns authorize URL)  |
| POST   | `/gmail/connect/callback`       | complete OAuth, persist connection   |
| POST   | `/gmail/reconnect`              | restart OAuth flow                   |
| POST   | `/gmail/disconnect`             | revoke @ Google + tombstone locally  |
| GET    | `/gmail/status`                 | connection + recent runs             |
| GET    | `/gmail/health`                 | live users.getProfile probe          |
| POST   | `/gmail/sync`                   | trigger sync (manual/initial/incr)   |
| GET    | `/gmail/sync/history`           | paginated SyncLog history            |
| GET    | `/gmail/threads`                | paginated thread rollups             |
| GET    | `/gmail/labels`                 | mirrored label catalogue             |
| POST   | `/gmail/labels/sync`            | queue label refresh                  |
| GET    | `/emails`                       | list metadata (filters: label,       |
|        |                                 | sender_domain, since)                |
| GET    | `/emails/{id}`                  | full metadata document               |
| GET    | `/emails/thread/{thread_id}`    | full conversation                    |

All endpoints require the platform `Principal` from Module 2.

---

## 14. Error Handling Strategy

| Failure                       | Detected by            | Recovery                                 |
|-------------------------------|------------------------|------------------------------------------|
| Refresh token invalid/revoked | `RefreshError`         | `GmailReauthRequired` → status `reauth_required`, UI prompts reconnect |
| 429 (rate/quota)              | HTTP status            | Exponential backoff, then `GmailQuotaExceeded` → sync `partial` |
| 5xx transient                 | HTTP status            | Exponential backoff (5 attempts)         |
| History cursor expired        | 404 on history.list    | Fall back to initial import              |
| No refresh_token from Google  | Callback validation    | `oauth_no_refresh_token` → prompt full consent |
| Missing scope                 | Callback validation    | `oauth_scope_missing` (422)              |
| Concurrent sync               | Redis NX lock          | Immediate `skipped:already_running`      |
| Celery task crash             | try/except in task     | `self.retry` up to 3× w/ 60s delay       |
| DB write failure              | `PyMongoError`         | Wrapped in `ExternalServiceError`        |

All domain errors surface through the shared `ErrorEnvelope` (Module 1).

---

## 15. Logging Strategy

Structured (structlog) events emitted at:

- `gmail_connected`, `gmail_disconnected` (connection lifecycle)
- `gmail_sync_reauth`, `gmail_sync_quota`, `gmail_sync_http_error`,
  `gmail_sync_failed` (per-run failure taxonomy)
- `gmail_retry` (each backoff attempt with status + delay)
- `gmail_history_gone` (fallback to initial import)
- `analysis_fanout_failed` (downstream enqueue failure)

Per-run counters (scanned/ingested/updated/skipped/api_calls/retries)
live in `sync_logs` so historical throughput is queryable in Mongo,
not just log storage.

---

## 16. Security Measures

- Refresh tokens encrypted at rest with AES-GCM (`core.encryption`).
- Access tokens never persisted (rebuilt per call).
- OAuth `state` server-minted, Redis-scoped, single-use.
- Granted scopes validated against required set — refuses partial consent.
- HTTPS-only OAuth redirect (enforced by Google + platform CORS).
- All endpoints authenticated via `Principal`; no anonymous access.
- Request bodies validated by Pydantic; length caps on subject/snippet/body.
- Disconnect revokes the token at Google **and** stops user watches.

---

## 17. Testing Strategy

- **Unit** (`test_gmail_extraction.py`): header parsing verdict extraction,
  URL normalisation + dedup, HTML/text source labelling.
- **Service-level** (add in Module 6 alongside the analyzer):
  mock `googleapiclient` to test initial + incremental branches without
  network I/O.
- **Repository**: reuse the `mongomock`-style in-memory fixture from
  `tests/conftest.py`.
- **Integration**: recorded Gmail fixtures (`fixtures/gmail_*.json`) fed
  through `EmailMetadataService.build()` and asserted end-to-end.

---

## 18. Production Deployment Recommendations

- **Quotas**: register a dedicated GCP project per environment, request
  the Gmail API quota increase to 2× peak concurrent users × 15-min cadence.
- **Beat cadence**: keep `*/15m` as the default; users on business plans
  can be moved to `*/5m` by adding a distinct beat entry.
- **Push notifications**: `users.watch` + Pub/Sub is the next step — the
  service already exposes `stop_watch`, and the incremental branch is
  push-ready (it only needs a starting `historyId`).
- **Horizontal scale**: `gmail.sync_user` is stateless outside of the
  Redis lock; scale worker replicas linearly with connected users.
- **Observability**: pipe `sync_logs` aggregations into the dashboard
  (throughput, retry rate, reauth rate) — no extra emitters needed.
- **Rotation**: OAuth client-secret rotation only requires re-issuing the
  credentials env var; refresh tokens keep working across rotations.
- **Data retention**: `sync_logs` TTL 90 d; `emails` uses soft delete +
  Module 3's `RetentionPolicy` sweep.
