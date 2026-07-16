# Phase 17 — Advanced Threat Detection & Fraud Detection Engine

Phase 17 is an **additive** correlation layer that strengthens existing
detection without replacing Modules 6 (AI), 7 (Threat), or 15 (Threat
Intel). It fuses header, domain, URL, language, AI-generation, behaviour,
and fraud signals into one explainable, evidence-based verdict.

## 1. Architecture

```
Incoming request  ─►  ThreatCorrelationService (async fan-out)
                       ├─ HeaderAnalysisService        (SPF/DKIM/DMARC/ARC)
                       ├─ DomainIntelligenceService    (typosquat, homograph, TLD)
                       ├─ URLIntelligenceService       (shorteners, IP, forms)
                       ├─ LanguageAnalysisService      (urgency, coercion, asks)
                       ├─ AIGeneratedDetector          (LLM-authored heuristics)
                       ├─ FraudDetectionService        (BEC, invoice, payroll…)
                       └─ BehaviorAnalysisService      (sender history / anomalies)
                            ↓
                       Risk correlation + weighting
                            ↓
                       Classification (safe / low / medium / high / critical)
                            ↓
                       RecommendationService  ─►  DetectionResult (Mongo)
                                                 FraudIndicator[]  (Mongo)
```

## 2. Fraud Detection Engine

Deterministic lexicon-based detectors for wire transfer, invoice, payroll,
banking-details change, vendor fraud, gift-card fraud, and BEC/CEO fraud
(executive hint + urgency + financial ask ⇒ `critical`). Findings are
persisted as `fraud_indicators` linked to the parent `detections` row.

## 3. Behaviour Analysis

Rolling `sender_behavior` profile per (user, sender): first-contact
detection, historical flag ratio, subject-length anomaly, trusted-sender
credit. Every analysis observes the current message and updates the
profile for the next round — persistence failures never break detection.

## 4. Language Analysis

Nine categorised regex families (urgency, fear, credential, financial,
gift card, crypto, romance, tech-support, government-impersonation) plus
grammar/whitespace/caps anomalies. Auditable and free of ML drift.

## 5. Header Analysis

Parses `Authentication-Results` (SPF/DKIM/DMARC/ARC), plus reply-to /
return-path mismatch and long Received chains. Weighted heavily for
DMARC fail.

## 6. Domain Intelligence

Levenshtein-based typosquat matching against a curated brand list, plus
punycode/Unicode, disposable, suspicious-TLD, deep-subdomain, digit/hyphen
heuristics.

## 7. URL Intelligence

Structural URL scoring: IP-URLs, shorteners, userinfo, non-standard
ports, credential keywords, nested URL in query, plus per-URL domain
intel.

## 8. AI-Generated Phishing Detection

Explainable heuristics: known LLM phrase count, prompt-leakage strings,
uniform sentence lengths, Shannon entropy. Returns
`confidence_ai_generated` in [0,1].

## 9. Risk Correlation Engine

Weighted linear correlation across all subsystems (header ×0.9, domain
×0.8, URLs ×0.4/each, language ×0.9, fraud ×1.0, AI ×0.6, behaviour ×1.0),
clamped to `[0, 100]`.

## 10. Threat Classification

| Score | Class |
|-------|-------|
| ≥85   | critical |
| ≥65   | high |
| ≥40   | medium |
| ≥15   | low |
| else  | safe  |

## 11. Risk Score

`risk_score` (0–100), `confidence` (0–1, function of active signal
sources + evidence density), `attack_complexity`
(low/medium/high), `potential_impact` (low/medium/high/critical, elevated
by BEC).

## 12. Recommendation Engine

Deterministic mapping from classification + fraud findings to a primary
recommendation (`open_safely | review | report_phishing | escalate`) and
admissible actions (`delete`, `block_sender`, `report_phishing`,
`escalate_to_admin`, `generate_evidence`, `archive`, `ignore`).

## 13. Celery Workers

`app.workers.detection_tasks`:
* `threat.detection.analyze_email(user_id, email_id)`
* `threat.detection.analyze_payload(user_id, payload)`

Registered on the `threat.*` route → `Q_THREAT` queue; retries with
exponential backoff (max 3).

## 14. Database

New collections:
* `detections` — full correlated verdict + subsystem outputs (soft-delete).
* `sender_behavior` — rolling per-user, per-sender profile.
* `fraud_indicators` — per-detection fraud evidence.

## 15. API

| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/api/v1/detection/analyze`         | Correlate on a stored email or inline payload |
| GET    | `/api/v1/detection/history`         | Paginated user history (optional `min_score`) |
| GET    | `/api/v1/detection/{id}`            | Full detection record |
| GET    | `/api/v1/risk-score/{id}`           | Slim score view |
| GET    | `/api/v1/fraud/history`             | Fraud indicators for the caller |

All endpoints require `CurrentUser`; every fetch is scoped to
`principal.user_id` and returns 404 on cross-user access.

## 16. Logging

`structlog` emits `detection.analyzed` (classification, risk_score,
categories, ms) and `detection.persist_failed` on write errors. Task
worker emits `detection.task.analyze_email` with input/output metadata.

## 17. Security

* Auth-required (JWT session middleware from Modules 1/11).
* Per-user scoping enforced in service + repository layers.
* Rate limiting inherits from SlowAPI (Module 11).
* Audit trail is the `detections` collection itself — soft delete only.

## 18. Performance

* Header, domain, URL, language, AI-generation, and fraud detectors run
  in parallel via `asyncio.to_thread`.
* Behaviour observation runs concurrently with the CPU-bound tasks.
* All detectors are dependency-light and deterministic → no cold-start.
* Correlation is O(#signals) with no external I/O beyond one Mongo write.

## 19. Testing

`app/tests/test_phase17_detection.py`: header parse + reply mismatch,
typosquat/TLD, IP + shortener URL, multi-category language, BEC + gift
card, AI-generated flags, classification thresholds, escalation
recommendation.

## 20. Enterprise Deployment Recommendations

* Provision the `threat` queue worker with concurrency sized to email
  ingest rate.
* Set `min_score` alerts on `/detection/history` for SOC dashboards.
* Feed `detections` into the analytics rollups (Module 10) to trend
  false-positive/negative rates.
* Extend `_BRAND_TARGETS` / disposable / shortener sets per deployment.
