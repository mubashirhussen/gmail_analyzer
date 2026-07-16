# Module 5 — Threat Intelligence Engine

Module 5 turns every email metadata record produced by Module 4 into a
signed, explainable **Threat Report** by fanning out to a curated set of
independent intelligence sources, folding intrinsic signals (headers,
authentication, attachment metadata, URL / domain features) into the
result, and persisting everything for downstream consumption by Module 6
(AI reasoning), Module 7 (analytics), and the frontend.

The engine is intentionally **opinion-free**: it produces structured
facts and deterministic scores. All narrative reasoning happens in
Module 6.

---

## 1. Threat Intelligence Architecture

```text
              +--------------------------+
              |   API   |   Celery       |   ← transport (Module 1)
              +----+----+-------+--------+
                   |            |
                   v            v
        +------------------------------------+
        |    ThreatEngineService (orchestr.) |
        +---+-------------------------+------+
            |                         |
   extractors                     scorer + report_service
   (URL/domain/IP/attach.)             |
            |                         v
            v               +----------------------+
  ProviderAggregationSvc    | ThreatReport +       |
  ├─ google_safe_browsing   | Indicators +         |
  ├─ virustotal             | Timeline (Mongo)     |
  ├─ urlscan                +----------------------+
  ├─ phishtank
  ├─ urlhaus
  ├─ rdap (WHOIS)
  ├─ abuseipdb
  └─ dns_ssl (native probes)
```

Provider isolation is absolute: every provider is a subclass of
`BaseProvider` and runs inside a per-call timeout + retry envelope.
Failures never propagate to peers or to the orchestrator.

## 2. Threat Analysis Pipeline

1. **Load email** (`EmailsRepository.find_by_id`).
2. **Extract artefacts**: URLs (already normalized during Module 4 sync
   are re-normalized here for safety), domains, sender identity, origin
   IP from `Received` chain, attachment metadata, attachment SHA-256
   (when Gmail exposed one).
3. **Provider fan-out** (`ProviderAggregationService`):
   * Cache lookup in `provider_results` per (provider, sha256(value))
     using per-provider TTL.
   * Cache miss → parallel `provider.run(client, kind, value)` calls,
     each bounded by `PROVIDER_TIMEOUT_S[slug]` and 2 retries with
     backoff.
   * Fresh outcomes persisted to `provider_results` for cache + audit.
4. **Intrinsic analysis**:
   * URL — `UrlAnalysisService` (shorteners, obfuscation, deep
     subdomains, IDN, typosquat, homograph).
   * Domain — `DomainAnalysisService` (age, WHOIS privacy, provider
     verdicts).
   * Header — `HeaderAnalysisService` (Received-hop count, forged
     chain, timestamp skew, missing message-id, suspect X-Mailer).
   * Auth — `AuthenticationAnalysisService` (SPF/DKIM/DMARC results,
     Reply-To / Return-Path / envelope / display-name mismatches).
   * Attachment — `AttachmentAnalysisService` (double extension,
     executables, macro Office, encrypted archives, known-malware
     SHA-256).
   * IP — `IpReputationService` (AbuseIPDB verdict, Tor, hosting).
5. **Score** — `ThreatScoreService.compute(indicators, providers_*)`
   produces `ScoreBundle` + verdict + category + recommended action
   using the deterministic weights in `config.ScoreWeights`.
6. **Report assembly** — `ThreatReportService.finalize` writes the
   report, bulk-upserts IOCs into `threat_indicators`, and appends
   timeline events.

## 3. Provider Integration Design

Every provider implements the same 3-symbol contract:

```python
class BaseProvider:
    slug: str
    kinds: tuple[ArtifactKind, ...]

    def enabled(self) -> bool: ...
    async def _call(self, client, kind, value) -> ProviderOutcome: ...
```

`ProviderOutcome` is the only shape the aggregator, scorer, and report
service ever see. Cross-cutting concerns (timeout, retries, caching,
telemetry) all live in `BaseProvider.run`, so new providers only write
the API-specific translation.

| Provider              | Kinds               | Key env                     | Default enabled |
| --------------------- | ------------------- | --------------------------- | --------------- |
| google_safe_browsing  | url                 | `GOOGLE_SAFE_BROWSING_KEY`  | if key present  |
| virustotal            | url, domain, hash   | `VIRUSTOTAL_API_KEY`        | if key present  |
| urlscan               | url, domain         | `URLSCAN_API_KEY` (opt.)    | always          |
| phishtank             | url                 | `PHISHTANK_APP_KEY` (opt.)  | always          |
| urlhaus               | url, domain         | none                        | always          |
| rdap                  | domain              | none                        | always          |
| abuseipdb             | ip                  | `ABUSEIPDB_KEY`             | if key present  |
| dns_ssl               | url, domain         | none                        | always          |

## 4-7. URL / Domain / Authentication / Header Flow

See per-service module docstrings — each analysis service produces a
homogeneous `*Indicator` dataclass consumed by the scorer.

## 8. Threat Scoring Algorithm

* Weights: `config.ScoreWeights` (env-overridable).
* Repeats: category weight × `1 + 0.25 × min(k, 3)-1` — grows
  sublinearly so five bad URLs is worse than one but never dominates
  arithmetic.
* Bands: `< 15 safe`, `< 35 low`, `< 60 medium`, `< 85 high`, else
  critical.
* `confidence = 0.4 × provider_coverage + 0.6 × (indicator_diversity/6)`
  capped in `[0.1, 1.0]`.
* Category derivation: precedence
  `malware > phishing > BEC > impersonation > safe`.

## 9-10. Schemas

* `ThreatReport` — one document per scan; embeds provider status
  snapshot, indicator rollup, evidence excerpt, recommended action,
  score bundle.
* `ThreatIndicator` — one row per artefact-severity; key
  `(threat_report_id, kind, value_hash)`.
* `ProviderResult` — every provider call (cached + audit).
* `ThreatTimelineEvent` — append-only per-report lifecycle stream.

## 11. Celery Task Architecture

```text
threat.scan_email(user_id, email_id, triggered_by)   ← Module 4 sync fanout
threat.scan_url(user_id, url, triggered_by)          ← user-initiated URL scan
threat.recheck(user_id, report_id)                   ← re-run with cache bypass
```

All tasks: `acks_late=True`, retry with backoff (max 3, jitter, cap 5m),
routed to the `threat` queue.

## 12. MongoDB Integration

New collections:

* `threats` — TTL: none (audit).
* `threat_indicators` — TTL: none.
* `provider_results` — TTL 30d recommended (index in `indexes.py`).
* `threat_timeline` — TTL 30d recommended.

Compound indexes:

* `provider_results (provider, artifact_hash, created_at DESC)`
* `provider_results (threat_report_id, created_at ASC)`
* `threat_timeline (threat_report_id, sequence)`

## 13. Redis Usage

* Circuit-breaker sentinels per provider (`threat:circuit:*`).
* Rate-limit windows (`threat:ratelimit:*`).
* Distributed scan lock (`threat:lock:email:*`) — prevents duplicate
  scans of the same email in parallel workers.

## 14. API Endpoints

```
POST   /api/v1/threats/scan          — scan an owned email
POST   /api/v1/threats/scan-url      — scan an arbitrary URL
POST   /api/v1/threats/recheck       — force re-scan (bypass cache)
GET    /api/v1/threats/history       — paginated report list
GET    /api/v1/threats/{id}          — report summary
GET    /api/v1/threats/{id}/report   — summary + IOCs + timeline
GET    /api/v1/threats/providers     — provider health snapshot
```

All routes are `Principal`-authenticated; ownership is checked against
`user_id` on every read.

## 15. Service Layer

* `ThreatEngineService` — orchestrator (no I/O logic).
* `ProviderAggregationService` — fan-out + cache.
* `UrlAnalysisService`, `DomainAnalysisService`, `HeaderAnalysisService`,
  `AuthenticationAnalysisService`, `AttachmentAnalysisService`,
  `IpReputationService` — pure functions over inputs.
* `ThreatScoreService` — deterministic scoring.
* `ThreatReportService` — persistence.

## 16. Repository Layer

* `ThreatReportRepository` — reports.
* `ThreatIndicatorRepository` — IOCs (bulk upsert).
* `ProviderResultRepository` — cache + health rollup.
* `ThreatTimelineRepository` — timeline stream.

## 17. Error Handling Strategy

| Failure                        | Handling                                    |
| ------------------------------ | ------------------------------------------- |
| provider timeout               | `status=timeout`; scan continues            |
| HTTP 429 rate-limit            | `status=rate_limited`; back off, no retry   |
| provider 5xx / network         | `status=unavailable`; retry × 2             |
| provider exception             | `status=error`; log with stack; scan cont.  |
| aggregator crash               | report `scan_status=failed`, timeline event |
| MongoDB write failure          | wraps into `ExternalServiceError` (500)     |

Partial outcomes are legitimate — `scan_status=partial` when at least
one provider errored but others succeeded.

## 18. Logging Strategy

Structured logs (structlog via `core.logging.get_logger`):

* `threat_scan_task_start` / `_completed` / `_failed`
* `provider_unhandled` — provider-level catastrophic crash
* `slow_query` — repository-level
* `provider_persist_failed` — cache write failed (never blocks scan)

Every log record inherits `user_id`, `device_id`, `request_id` from
`core.context`.

## 19. Testing Strategy

* `test_threat_score.py` — deterministic scorer, categories, coverage.
* `test_threat_normalizer.py` — URL / domain / email normalization,
  Damerau-Levenshtein, typosquat.
* `test_threat_auth_headers.py` — SPF/DKIM/DMARC parsing, mismatches,
  origin IP extraction, timestamp anomalies.

Provider modules are covered by contract tests that stub `httpx` at the
transport layer (add in `test_providers_*.py` per provider).

## 20. Production Deployment Recommendations

* Run the `threat` Celery queue on a dedicated worker pool sized to
  provider concurrency limits (VirusTotal 4 req/min on free tier — set
  `--concurrency=2`).
* Cache TTLs (`config.PROVIDER_CACHE_TTL`) balance provider quotas vs
  detection freshness; tighten `virustotal` in high-throughput tenants.
* Rotate API keys through `add_secret` and never inline them.
* Add `provider_results.created_at` TTL index with
  `expireAfterSeconds = max(cache_ttl)` in production once traffic
  volume is observed.
* Expose `/threats/providers` to SRE dashboards — a sudden climb in a
  provider's `error_rate_1h` is the earliest indicator of an upstream
  outage.
* All egress traffic must go through the outbound proxy; provider
  hostnames must be allow-listed at the network boundary.

---

**Downstream contract for Module 6 (AI reasoning):** consume
`ThreatReport` + `ThreatIndicator[]` + `ThreatTimelineEvent[]`. The AI
layer must never re-call providers directly — it only interprets the
structured evidence this module produces.
