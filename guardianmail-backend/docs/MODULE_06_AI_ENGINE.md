# Module 6 — AI Analysis Engine

The AI Analysis Engine is the *explainable reasoner* on top of the
Threat Intelligence Engine (Module 5). It never reads Gmail data
directly — the only permitted input is a persisted `ThreatReport`.

---

## 1. Architecture

```
              ┌─────────────────────────────────────┐
              │           API / Celery              │
              │  POST /api/v1/ai/analyze            │
              │  ai.analyze  ai.reanalyze           │
              └───────────────┬─────────────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │   AIAnalysisService      │
                 │   (orchestrator, lock)   │
                 └───┬────────┬────────┬────┘
                     │        │        │
     ┌───────────────┘        │        └───────────────┐
     ▼                        ▼                        ▼
PromptBuilder          GeminiClient           AIValidationService
     │                        │                        │
     └────────────┬───────────┴───────────┬────────────┘
                  ▼                       ▼
        ConfidenceService        RecommendationService
                  │                       │
                  └───────────┬───────────┘
                              ▼
                   EducationalContentService
                              │
                              ▼
                  ReportGenerationService
                              │
                              ▼
             ai_reports  +  ai_decision_history
```

## 2. Decision Pipeline

`ThreatReport → Feature Normalisation → Prompt Construction →
LLM Analysis → Consistency & Grounding Validation → Confidence
Aggregation → Recommendation Generation → Educational Enrichment →
Persistence (ai_reports, ai_decision_history)`

Idempotency: `(threat_report_id, prompt_hash)`. `force=True` bypasses
the cache to re-run analysis when a new prompt version rolls out.

## 3. Prompt Builder

* Deterministic — inputs sorted, timestamps stripped, JSON compacted.
* Grounded — the prompt lists every indicator/evidence category so the
  model can only cite what actually exists.
* Bounded — payload capped at `AIEngineConfig.max_prompt_chars` to
  prevent token blow-up.
* Fingerprinted — `sha256(prompt_version + system + user)` becomes
  `prompt_hash` on `AIReport` for reproducibility.

## 4. JSON Output Schema

Enforced by `AIValidationService`:

```
verdict, risk_level, attack_type, likely_objective,
trust_score_adjustment, threat_summary, executive_summary,
detailed_explanation, reasoning[], evidence_used[],
possible_consequences[], user_impact, model_confidence,
immediate_actions[], long_term_recommendations[], educational_tips[],
technical_notes[]
```

Verdict enum: `safe, suspicious, spam, phishing, credential_theft,
business_email_compromise, malware, invoice_fraud, payment_scam,
identity_theft, fake_login, qr_phishing, unknown`.

## 5. Explainability & Grounding

`evidence_used[].category` values are cross-checked against the
ThreatReport's `evidence[]` and `indicators.top[]`. Cited categories
that do not exist upstream increment `hallucination_score`; a report
with `hallucination_score > 0.35` is marked `validation_passed=false`
and recorded as `outcome=degraded` in decision history.

## 6. Confidence

Weighted combination of five axes (0..100):

| Axis                | Weight | Source                                          |
|---------------------|--------|-------------------------------------------------|
| evidence_strength   | 0.30   | count of validated evidence citations           |
| provider_agreement  | 0.25   | `providers_ok / providers_total`                |
| model_confidence    | 0.20   | LLM self-report                                 |
| data_completeness   | 0.15   | presence of evidence / URLs / domains / ...     |
| reliability         | 0.10   | validation pass + reasoning count               |

## 7. Recommendations

`RecommendationService` de-duplicates, prioritises, and — for `high`
and `critical` verdicts — force-injects the non-negotiable baseline:
"do not click", "do not reply", "report to security".

## 8. Educational Guidance

`EducationalContentService` enriches the LLM's tips with curated,
verdict-specific guidance (never fear-based) so every report includes
at least one high-quality takeaway.

## 9. AI Safety

* Strict JSON mode (`response_mime_type=application/json`).
* Every claim must reference an existing indicator.
* Missing data explicitly disclosed instead of invented.
* Deterministic heuristic fallback when the LLM is unreachable — the
  fallback returns `verdict=unknown, risk_level=medium` with low
  confidence rather than fabricating a verdict.

## 10. Celery Task Architecture

| Task            | Queue | Purpose                              |
|-----------------|-------|--------------------------------------|
| `ai.analyze`    | `ai`  | Fresh analysis of a ThreatReport     |
| `ai.reanalyze`  | `ai`  | Force re-analysis (`force=true`)     |

Both tasks retry with exponential backoff. `AIAnalysisService` uses a
Redis lock (`ai:lock:{threat_report_id}`) to prevent concurrent runs.

## 11. MongoDB Collections

| Collection              | Purpose                                     |
|-------------------------|---------------------------------------------|
| `ai_reports`            | Latest AI verdict per threat report         |
| `ai_prompts`            | Versioned prompt templates (audit + A/B)    |
| `ai_decision_history`   | Append-only decision log (audit + drift)    |

Indexes registered in `app/database/indexes.py` cover user timelines,
threat report joins, verdict filtering, prompt-version drift analysis,
and model-version comparisons.

## 12. Redis Usage

* `ai:lock:{threat_report_id}` — concurrency guard (TTL 120s).
* `ai:cache:{prompt_hash}` — reserved for future output caching.
* `ai:rate:{user_id}:{bucket}` — reserved for per-user rate limiting.

## 13. API Endpoints

| Method | Path                          | Purpose                            |
|--------|-------------------------------|------------------------------------|
| POST   | `/api/v1/ai/analyze`          | Analyse a ThreatReport             |
| POST   | `/api/v1/ai/reanalyze`        | Force re-analysis                  |
| GET    | `/api/v1/ai/report/{id}`      | Fetch a stored AI report           |
| GET    | `/api/v1/ai/history`          | Paginated decision history         |
| GET    | `/api/v1/ai/models`           | Discoverable model catalogue       |

Every endpoint requires `Principal` and is user-scoped.

## 14. Error Handling

| Failure                | Response                                      |
|------------------------|-----------------------------------------------|
| LLM timeout / 429      | Retry (Celery). Runtime → heuristic fallback. |
| Malformed JSON         | Retry, then heuristic fallback.               |
| Validation failure     | Persist as `status=degraded`, `outcome=degraded`. |
| Missing ThreatReport   | 404 from API.                                 |
| Unauthenticated        | 401 from `get_principal`.                     |

## 15. Logging

Structured events: `ai.analysis.completed`, `ai.llm.timeout`,
`ai.llm.malformed`, `ai.llm.rate_limited`, `ai.llm.unavailable`,
`ai.analyze.failed`. Every event carries `report_id`,
`threat_report_id`, `verdict`, `duration_ms`.

## 16. Testing

`app/tests/test_ai_engine.py` covers:
* Prompt determinism (`prompt_hash` reproducibility).
* Validator: verdict enum, hallucinated-category detection,
  score/risk_level consistency.
* Confidence axis calculation.
* Recommendation baseline enforcement for critical verdicts.

## 17. Production Deployment

* Provision `GEMINI_API_KEY` (or equivalent) as an encrypted secret.
* Dedicate a Celery worker to the `ai` queue with lower concurrency
  than the `default` queue to keep costs bounded.
* Alert on `ai.llm.unavailable`, `ai.llm.rate_limited`, and rising
  `hallucination_score` per prompt version.
* Roll new prompts as new `AIPromptTemplate` rows and A/B on
  `prompt_version` before flipping the active flag.
