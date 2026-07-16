# Phase 16 — Enterprise Explainable AI Security Copilot

Phase 16 is an **additive** layer on top of the existing AI Analysis Engine
(Module 6) and Threat Intelligence Platform (Module 15). It transforms
`/api/v1/copilot/*` into an **evidence-anchored** copilot that explains
GuardianMail scan results using ONLY verified platform data. No business
logic, schemas, or public APIs from previous modules were modified.

## 1. AI Copilot Architecture

```
User Question
   ↓
[API] /api/v1/copilot/{chat,explain,summarize}
   ↓
CopilotService
   ├─ ContextService  → verified evidence bundle (BuiltContext)
   ├─ PromptBuilder   → SYSTEM + USER prompt (JSON schema locked)
   ├─ ProviderRouter  → OpenAI | Gemini | Azure | Anthropic | Ollama | Stub
   ├─ ResponseValidator → JSON parse + evidence grounding
   ├─ ConversationService → short-lived investigation memory
   └─ EducationalService  → curated topic library
   ↓
Explainable Response (summary, evidence[], indicators, reasoning,
                      confidence, recommended_action, tip, concepts)
```

## 2. Context Building

`ContextService.build(user_id, scope)` returns `BuiltContext` populated
exclusively from GuardianMail collections:

| Source          | Repository                     |
|-----------------|--------------------------------|
| threat report   | `ThreatReportRepository`       |
| email + headers | `EmailsRepository`             |
| providers       | `ProviderResultRepository`     |
| indicators      | `ThreatIndicatorRepository`    |
| attachments     | `AttachmentRecordsRepository`  |
| OCR             | `OcrReportsRepository`         |
| evidence pack   | `EvidencePacksRepository`      |
| history (sender)| `ThreatReportRepository`       |

Ownership is verified on every fetch (`user_id` match). Missing sections
are recorded in `BuiltContext.missing` so the validator can flag gaps.

## 3. Prompt Builder

* `SYSTEM_PROMPT` hard-locks the model to GuardianMail evidence, forbids
  hallucination, forbids general-purpose chatting, immunises against
  prompt-injection inside email/OCR/URL content, and mandates a **strict
  JSON schema** for the response.
* The user prompt embeds a slimmed JSON payload of the context plus at
  most the last 6 turns of conversation (continuity only, never treated
  as evidence).

## 4. Provider Abstraction

`ProviderRouter` selects providers by priority (env-configured) and
transparently retries + falls back to the deterministic `StubProvider`
so the copilot never returns 5xx to end users. Supported providers:
OpenAI, Azure OpenAI, Google Gemini, Anthropic Claude, Ollama, plus
`stub` for offline/CI. Selection can be overridden per request.

## 5. Response Validation

`ResponseValidator` parses the JSON, fills missing required fields,
clamps `confidence` to `[0,1]`, and **grounds every `evidence[].value`
against the context payload**. Unsupported evidence down-scores
confidence and, if 100% unsupported, marks the response `ok=false`.
Missing evidence anchor → hard `ok=false` with `no_evidence_anchor`.

## 6. Explainable AI Framework

Every response includes:
`summary · evidence · threat_indicators · ai_reasoning · confidence ·
recommended_action · educational_tip · related_concepts`.
Evidence items are copied verbatim from context so they are auditable.

## 7. Educational Engine

`EducationalService` serves a curated in-repo library (phishing, BEC,
invoice fraud, SPF/DKIM/DMARC, QR phishing, safe browsing, etc.). Never
LLM-generated → deterministic and always available.

## 8. Conversation Architecture

Conversations (`copilot_conversations`) are scoped to a GuardianMail
artifact and store the last N turns in `copilot_messages`. Memory is
intentionally short (6 turns). `DELETE /copilot/history` wipes all user
messages and archives conversations — no permanent user-level memory.

## 9. RAG Layer

Lightweight, deterministic RAG limited to: current threat report, current
scan, current OCR, current evidence pack, current draft, and last 5
historical threats for the same sender. Never touches unrelated user
data.

## 10. API Design

| Method | Path                                              | Purpose |
|--------|---------------------------------------------------|---------|
| POST   | `/api/v1/copilot/chat`                            | Free-form Q&A within scope |
| POST   | `/api/v1/copilot/explain`                         | Aspect-specific explanation |
| POST   | `/api/v1/copilot/summarize`                       | Executive/technical/user summary |
| GET    | `/api/v1/copilot/history`                         | Paginated conversation list |
| GET    | `/api/v1/copilot/history/{id}/messages`           | Full conversation transcript |
| DELETE | `/api/v1/copilot/history/{id}`                    | Soft-delete conversation |
| DELETE | `/api/v1/copilot/history`                         | Wipe all copilot history |
| GET    | `/api/v1/copilot/providers`                       | List registered providers |
| GET    | `/api/v1/copilot/education/topics`                | Educational topic index |
| GET    | `/api/v1/copilot/education/{topic}`               | Topic explanation |

## 11. Database Integration

New collections (additive):
* `copilot_conversations` — investigation sessions.
* `copilot_messages` — role/content plus provider/latency/token/validation
  metadata and evidence refs.

## 12. Celery Integration

Long summarisations and incident-report generation reuse the Celery
infrastructure from Modules 10–11 (`analytics_platform_tasks`) by
enqueuing calls to `copilot_service.summarize`; the request/response API
remains synchronous for interactive UX.

## 13. Logging Strategy

`structlog` logs prompt provider, latency, token usage, and validation
result on every call; provider failures emit `copilot.provider_failed`.

## 14. Security Strategy

* Auth-required on every endpoint (`CurrentUser`).
* Strict per-user scoping on all repository fetches.
* Prompt-injection scrubber on user questions; hard system rule to
  ignore instructions embedded in email/OCR/URL/attachment content.
* Rate limiting inherits from SlowAPI (Module 11).
* Conversation isolation: cross-user reads return 404.
* Full audit metadata stored on each assistant message.

## 15. Performance Optimization

* Prompt payload slimmed to only the fields the copilot needs.
* Context capped to the top providers/indicators/attachments/OCR docs.
* Provider fallback avoids retry storms; Stub provider guarantees SLA.

## 16. Testing Strategy

`app/tests/test_phase16_copilot.py` covers: prompt determinism, stub
provider JSON validity, validator grounding, missing-anchor refusal,
prompt-injection neutralisation, provider fallback, and educational
library integrity.

## 17. Production Deployment Recommendations

* Configure at least one real provider via env
  (`OPENAI_API_KEY`, `AZURE_OPENAI_*`, `GEMINI_API_KEY`,
  `ANTHROPIC_API_KEY`, `OLLAMA_URL`) — the stub remains as safety net.
* Keep `MAX_TURNS=6` unless memory retention policy changes.
* Alert on validator failure rate (`copilot.provider_failed`,
  `no_evidence_anchor`, `unsupported_evidence`).
