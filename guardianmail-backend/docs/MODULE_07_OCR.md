# Module 7 — OCR & Attachment Security Analysis

Additive module. No existing module is modified beyond three registration
points: `app/main.py` (router), `app/database/indexes.py` (indexes for two
new collections), and the model / repository barrels.

## 1. Architecture

```
API / Worker
    │
    ▼
OCRPipeline ──► validate → sha256 dedup → text extraction
                                        → pattern extraction (regex)
                                        → sensitive-data detection
                                        → QR scan (image + rasterised PDF)
                                        → security indicators
                                        → document metadata
                                        → attachment analysis
                                        → persist OCRReport
                                        → optional fan-out
                                             ├─► Module 5 (Threat Intel)
                                             └─► Module 6 (AI Engine)
```

## 2. Document processing pipeline

Every request lands in `OCRPipeline.run(...)`. The pipeline is synchronous
(CPU-bound work), idempotent by `(user_id, sha256)`, and never throws once
past validation — pipeline errors are recorded on the report.

## 3. Image processing flow

`services/ocr/preprocess.py` prefers OpenCV (greyscale → NLM denoise →
deskew → adaptive threshold) and falls back to Pillow (EXIF-transpose +
autocontrast) when `cv2` isn't installed. Enhanced bytes are re-encoded
as PNG for downstream OCR.

## 4. PDF processing flow

`services/ocr/text_extraction._pdf` uses PyMuPDF for searchable pages
(cheap) and rasterises + OCRs pages that yield < 20 chars of text (a
proxy for scanned pages). Falls back to `pypdf` when PyMuPDF is absent.

## 5. QR analysis flow

`services/ocr/qr_scanner.scan` handles images directly and PDFs by
rasterising each page at 220 DPI. Payloads are classified into
{url, email, phone, upi, payment, wifi, vcard, text}. URLs are forwarded
to Module 5 during the fan-out step.

## 6. Sensitive data detection

`services/ocr/sensitive_detector.detect` returns a `SensitiveSummary`
with per-category counts and up to 3 masked samples per category. Raw
values are never persisted. Card numbers are filtered by Luhn.

Detected classes: `credit_card`, `iban`, `upi`, `aadhaar`, `pan`,
`passport`, `jwt`, `aws_access_key`, `aws_secret_key`, `google_api_key`,
`azure_key`, `private_key`, `password`, `api_key`.

## 7. Attachment analysis

`services/ocr/attachment_analyzer.analyze` computes SHA-256 and flags:
double-extension, executable extension, archive, macros (docx/xlsx/pptx
member inspection + legacy OLE heuristic), password-protected packages,
embedded objects, extracted hyperlinks. `known_bad_hash` is a
placeholder wired to the future malware-hash provider.

## 8. OCR report schema

`app/models/ocr_report.py::OCRReport` — persisted in `ocr_reports`:

- `status`, `error_code`, `error_message`, `retry_count`
- `extracted_text` (bounded to 200 KB), `text_truncated`, `ocr_confidence`,
  `processing_time_ms`, `page_count`, `engines_used`
- `patterns` — urls / domains / emails / phones / ips / dates / amounts /
  masked account numbers / reference / invoice / tracking
- `qr_results`, `sensitive`, `security_indicators`, `metadata`, `attachment`
- `threat_report_id`, `ai_report_id`, `forwarded_to_*_at` for pipeline
  linkage

## 9. Database integration

Collections + indexes added in `app/database/indexes.py`:

- `ocr_reports` — `(user_id, created_at DESC)`, `(user_id, status,
  created_at DESC)`, `(user_id, attachment.sha256)`,
  `(email_id, created_at DESC)`, `(threat_report_id)`, `(ai_report_id)`.
- `attachment_records` — `(user_id, sha256)` unique,
  `(sha256, last_seen_at DESC)`, `(user_id, last_seen_at DESC)`,
  `(user_id, risk_flags)`.

## 10. Celery tasks

Queue `ocr` (already routed in `celery_app.py::task_routes`):

- `ocr.extract` — legacy plain-text extraction (kept for callers).
- `ocr.process_upload` — new full pipeline; auto-retry with backoff.
- `ocr.forward_to_threat` — re-fan-out an existing report to Module 5.
- `ocr.forward_to_ai` — re-fan-out to Module 6.

## 11. Redis usage

`services/ocr/redis_keys.py` reserves namespaces for future concurrency
locks (`ocr:lock:report:{id}`), upload-dedup (`ocr:dedup:{user}:{sha}`),
and per-user rate limits. The report table already dedupes by SHA-256,
so no lock is currently taken.

## 12. API endpoints

Router mounted under `/api/v1/ocr`:

- `POST /ocr/upload` — JSON with base64 body.
- `POST /ocr/upload/multipart` — direct `multipart/form-data`.
- `POST /ocr/analyze` — re-run downstream fan-out for an existing report.
- `GET  /ocr/report/{id}` — full report detail.
- `GET  /ocr/history` — paginated summaries.

All endpoints require an authenticated `Principal`.

## 13. Service layer

`services/ocr/` — `validation`, `preprocess`, `text_extraction`,
`pattern_extractor`, `sensitive_detector`, `qr_scanner`,
`metadata_extractor`, `attachment_analyzer`, `security_indicator_service`,
`ocr_pipeline`.

## 14. Repository layer

- `OCRReportRepository` — `find_by_hash`, `list_for_user`, `set_status`,
  `attach_threat_report`, `attach_ai_report`.
- `AttachmentRecordRepository` — `upsert` (dedupes per user), `find_by_hash`.

## 15. Error handling

- `OCRValidationError` — 415 / stable codes: `ocr_empty_upload`,
  `ocr_file_too_large`, `ocr_unsupported_mime`.
- Pipeline failures → `report.mark_failed('ocr_pipeline_error', str(e))`.
- Celery tasks: `autoretry_for=(Exception,)`, `retry_backoff=True`,
  `max_retries=3`, `retry_backoff_max=120s`, jittered.

## 16. Logging

Structured logs on every stage boundary. Slow queries in the repo layer
inherit `BaseRepository._timed` (250 ms threshold). Pipeline logs:
`ocr_dedup_hit`, `ocr_pipeline_failed`, plus per-format
`pdf_ocr_page_failed`, `qr_scan_pdf_failed`, `metadata_extract_failed`.

## 17. Security

- Filename sanitised (`sanitize_filename`) — path components stripped.
- MIME allow-list (`ALLOWED_MIMES`) and hard 20 MiB size cap.
- SHA-256 hash of every attachment; raw bytes never persisted.
- Sensitive values masked before storage (last-4 pattern).
- All endpoints behind `Depends(get_principal)` — no anonymous uploads.
- Executable, macro-enabled, encrypted, and double-extension files are
  flagged but not blocked (surfaced via `attachment.risk_flags`).

## 18. Testing

`app/tests/test_ocr_pipeline.py` covers:

- filename sanitation & MIME/double-extension validation,
- URL / email / phone / domain extraction,
- Luhn-validated card, JWT and AWS-key detection,
- shortener + typosquat + urgent-language indicators.

## 19. Production deployment

- Deploy a dedicated `ocr` Celery worker with system packages:
  `tesseract-ocr`, `libtesseract`, `libzbar0`, `poppler-utils`, plus
  Python extras: `pymupdf`, `pdfplumber`, `python-docx`, `openpyxl`,
  `pyzbar`, `Pillow`, `opencv-python-headless`, `pytesseract`.
- Autoscale `ocr` queue on queue depth, not CPU — bursts come from
  Gmail sync back-fills.
- Cap concurrency to `min(CPU, 4)` per worker; OCR is memory-heavy.
- Wire a malware-hash provider (VirusTotal file endpoint, Team Cymru
  MHR) to populate `AttachmentAnalysis.known_bad_hash`.
- Add virus-scan hook (ClamAV) before persistence when raw bytes must
  be retained downstream; today the pipeline discards bytes after
  extraction, which sidesteps AV requirements.
