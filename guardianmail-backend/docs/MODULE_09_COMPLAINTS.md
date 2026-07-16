# Module 9 — Complaint Management & Digital Evidence Platform

Module 9 turns verified threat + AI reports into (a) signed forensic
evidence packs and (b) structured complaint drafts users can review and
manually file with cybercrime portals, CERT-In, or their internal SOC.

The module never auto-submits complaints — it only prepares high-quality
downloadable artefacts.

---

## 1. Architecture

```
Threat Report ─┐
AI Report      ├─▶ EvidenceValidator ─▶ Bundle Assembler ─▶ IntegrityService
Indicators ────┘                                                │
                                                                ▼
                                                 EvidencePack (Mongo)
                                                                │
                                                                ▼
                                              ExportService (pdf/docx/json/zip/csv)
                                                                │
                                                                ▼
                                       ComplaintDraft (template registry)
                                                                │
                                                                ▼
                                          User Review → Export → History
                                                                │
                                                                ▼
                                                        ReminderService
```

## 2. Evidence Generation Pipeline

1. `validate_for_evidence(user_id, threat_id)` — verifies threat + AI reports
   exist, required metadata is present, and the caller owns the threat.
2. `_assemble_bundle` gathers indicators, URLs, headers, authentication
   results, attachments, OCR/QR data, provider results, and timeline events.
3. `integrity_envelope` wraps the manifest with `sha256` + HMAC-SHA256
   signature scoped to `SECRET_KEY`.
4. Pack persisted to `evidence_packs` collection.
5. `evidence_custody` receives a `pack_generated` event (append-only).

## 3. Digital Evidence Model

Collections created by this module:

| Collection            | Purpose                                     |
| --------------------- | ------------------------------------------- |
| `evidence_packs`      | manifests + integrity envelope + counters   |
| `evidence_custody`    | append-only chain-of-custody events         |
| `evidence_downloads`  | audit log for every export                  |
| `complaint_reminders` | scheduled reminders (`tomorrow`/`next_week`/`custom`) |
| `complaint_templates` | optional DB overrides for the built-in catalogue |

Existing `complaints` collection is reused; new fields (`locale`,
`template_version`, `draft_hash`, `evidence_hash`, `download_count`,
`last_accessed_at`) are added additively.

## 4. Complaint Template Architecture

Templates are addressable as `(destination, category, locale, version)`.

- 13 categories: phishing, credential_theft, bec, invoice_fraud,
  identity_theft, malware, fake_login, payment_scam, lottery_scam,
  investment_scam, crypto_scam, social_engineering, unknown.
- 6 destinations: cybercrime_gov_in, cert_in, org_security_team,
  corporate_soc, internal_security, custom.
- Jinja2 rendering with `StrictUndefined` — missing variables raise
  instead of producing corrupted drafts.
- DB overrides in `complaint_templates` win over the packaged defaults
  without a redeploy.

## 5. Evidence Pack Structure

Every pack ships with:

- `manifest.json` — canonical JSON (`sort_keys=True`) covering summary,
  message metadata, auth results, indicators, URLs, attachments, OCR,
  QR analysis, provider results, timeline, and AI report.
- `indicators.csv` — spreadsheet-friendly triage view.
- `summary.pdf` — printable investigator summary (ReportLab).
- `summary.docx` — editable summary (python-docx).
- `INTEGRITY.txt` — pack ID + SHA-256 + HMAC signature + verification
  instructions.

## 6. Chain of Custody

`app/services/evidence/integrity.py::record_custody_event` writes an
immutable record to `evidence_custody` for every lifecycle event
(`pack_generated`, `exported`, `complaint_drafted`, …). Records are
never updated or deleted; retrieval is via `custody_trail(pack_id)`.

## 7. Integrity Verification

Canonical manifest bytes are produced via `canonical_json`
(deterministic key ordering + separators). `verify_envelope(envelope)`
returns `(ok, reason)` and is exposed via
`GET /api/v1/evidence-platform/packs/{id}/verify` so investigators can
prove the artefacts have not been tampered with.

## 8. Export Pipeline

`ExportService.render(bundle, fmt)` supports `pdf | docx | json | zip | csv`.
Each export records a `downloaded` custody event and appends to
`evidence_downloads` for audit.

## 9. Reminder Architecture

`ReminderService.schedule(user, complaint, preset|custom)` persists to
`complaint_reminders`. Celery beat runs
`complaints_platform.sweep_reminders` which fires notifications through
the Module-8 notification service and marks the reminder `sent`.

## 10. Database Integration

Indexes added in `app/database/indexes.py`:

- `evidence_packs`: `(user_id, created_at desc)`, `sha256`.
- `evidence_custody`: `(pack_id, at)`.
- `evidence_downloads`: `(user_id, at desc)`, `(pack_id, at desc)`.
- `complaint_reminders`: `(status, fire_at)`, `(user_id, fire_at)`.
- `complaint_templates`: `(destination, category, locale, version)`
  unique.

## 11. Celery Task Architecture

Added tasks (queue `complaints`):

| Task | Purpose |
| ---- | ------- |
| `complaints_platform.generate_evidence_pack` | build + persist a pack |
| `complaints_platform.generate_complaint_draft` | pack + template rendering |
| `complaints_platform.export_pack` | offline export to any format |
| `complaints_platform.sweep_reminders` | fire due reminders every 5 min |

## 12. Redis Usage

None new for this module — dispatching, rate limiting, and dedup all
reuse the Module-8 `TaskDispatcherService` primitives.

## 13. API Endpoints

Complaints (prefix `/api/v1/complaint-platform`):
- `GET  /templates`
- `POST /complaints/generate`
- `GET  /complaints/history`
- `GET  /complaints/{id}`
- `PATCH /complaints/{id}`
- `PATCH /complaints/{id}/status`
- `DELETE /complaints/{id}`

Evidence (prefix `/api/v1/evidence-platform`):
- `POST /generate`
- `GET  /packs/{id}`
- `GET  /packs/{id}/verify`
- `GET  /packs/{id}/custody`
- `GET  /packs/{id}/download?fmt=pdf|docx|json|zip|csv`
- `POST /packs/{id}/download-token?fmt=…` — signed short-lived token
- `GET  /downloads/history`

Reminders (prefix `/api/v1/complaint-reminders`):
- `POST /`, `GET /`, `DELETE /{id}`

## 14. Service Layer

`ComplaintPlatformService` (`platform_service.py`), `ExportService`
(`exporters.py`), `IntegrityService` (`integrity.py`),
`EvidenceValidationService` (`validator.py`), `ReminderService`
(`reminder_service.py`), `TemplateService` (`template_registry.py`),
`DownloadAuditService` (`download_logs.py`).

## 15. Repository Layer

Reuses existing `ComplaintRepository` / `EvidencePackRepository` for
canonical entities, and adds direct-Motor helpers for the new
append-only collections (`evidence_custody`, `evidence_downloads`,
`complaint_reminders`).

## 16. Error Handling Strategy

- Validation failures raise `ValueError` translated to HTTP `400`.
- Missing artefacts raise `ValueError` translated to HTTP `404`.
- Export failures inside the ZIP fall back to `.error.txt` entries so
  partial bundles are still delivered.
- Celery tasks retry with exponential backoff (`default_retry_delay`
  15s, `max_retries` 3).

## 17. Logging Strategy

- Every custody event is a structured log line via the `evidence_custody`
  collection.
- Downloads log the requesting IP + user-agent + size.
- Celery hooks (Module 8) already emit start/complete/failure metrics
  for the new tasks.

## 18. Security Strategy

- All routes gated by `require_user`; ownership enforced at the query
  layer (`user_id` filter on every read).
- Chain-of-custody + evidence packs are append-only; edits go through
  history entries only.
- HMAC-SHA256 signatures over canonical JSON detect any tampering.
- Signed short-lived download tokens (`hmac_signature`, TTL 5 min).
- Complaint submissions are never posted to external URLs; users must
  download and file manually.
- Rate limiting inherits from FastAPI slowapi limiter.

## 19. Testing Strategy

`app/tests/test_complaint_platform.py` covers:
- canonical-JSON determinism, hash + HMAC verification, tamper detection,
- template catalogue completeness across all 13 × 6 combinations,
- template rendering with a fully-populated context,
- JSON/CSV/ZIP exporter output shape and MIME dispatch.

Integration + performance tests should target the Celery task pipeline
in the shared test harness.

## 20. Production Deployment

- ReportLab and python-docx are pure Python — no native deps beyond
  the standard Linux fonts already bundled.
- Ensure `SECRET_KEY` is long (>= 32 chars) and rotated per policy —
  it backs both HMAC signatures and download tokens.
- Beat schedule adds `complaints-platform-reminders` every 5 minutes;
  scale the `complaints` queue worker independently.
- Optional: mount object storage for large ZIPs if download traffic
  grows — the manifest and integrity envelope stay in Mongo, so the
  swap is transparent.
