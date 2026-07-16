# Module 15 — Enterprise Threat Intelligence Platform

> Additive. Existing `services/url_scan/scanner.scan_urls` and
> `services/scoring/*` remain unchanged. Phase 15 introduces a
> pluggable, cache-backed, multi-provider orchestrator that any
> subsystem can opt into.

New surface:

- `app/services/threat_intel/schemas.py` — `NormalizedProviderResult`, `ThreatVerdict`
- `app/services/threat_intel/providers.py` — adapters + `DEFAULT_PROVIDERS`
- `app/services/threat_intel/heuristics.py` — local detection engine
- `app/services/threat_intel/correlation.py` — score / confidence / verdict
- `app/services/threat_intel/orchestrator.py` — parallel fan-out, Redis cache
- `app/tests/test_phase15_threat_intel.py` — 12 unit tests

---

## 1. Architecture

```
┌────────── Incoming email / uploaded artifact ─────────┐
│  URLs   Body/OCR text   Attachments   Email headers   │
└──────────────────────┬────────────────────────────────┘
                       ▼
         ┌────────── Orchestrator ──────────┐
         │ Redis L2 cache (ti:v1:<url>)     │
         │ ── on miss ──►                   │
         │  parallel fan-out to providers   │
         │  per-provider timeout + retry    │
         └───────────┬──────────────────────┘
                     ▼
     ┌── Heuristic engine ──┐   ┌── Provider adapters ──┐
     │ typosquat, shortener │   │ GSB, VT, URLScan,     │
     │ IP-URL, urgency,     │   │ URLHaus, OpenPhish,   │
     │ credential harvest,  │   │ PhishTank, AbuseIPDB, │
     │ BEC, macro/exe files │   │ OTX, RDAP             │
     └───────────┬──────────┘   └───────────┬───────────┘
                 └────────────┬─────────────┘
                              ▼
                   Correlation & Confidence
                              ▼
                       ThreatVerdict
             (verdict, severity, score, confidence,
              indicators, reasons, recommendations)
                              ▼
                    Persist → threats collection
```

## 2. Threat Orchestrator

`orchestrator.analyze_url(url)` and `orchestrator.analyze_artifact(...)`:

- Parallel `asyncio.gather` with per-provider `asyncio.wait_for(TIMEOUT+1)`.
- Graceful degradation: missing keys → `skipped`; exceptions → `error`;
  slow provider → `timeout`; correlation still runs on partial evidence.
- Redis L2 cache (`ti:v1:<url>`), 6 h TTL for positive verdicts,
  30 min for clean verdicts. Cache read/write failures never break the flow.

## 3. Multi-Provider Integration

Providers registered in `DEFAULT_PROVIDERS`:

| Provider | Key required | Weight |
|---|---|---|
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_KEY` | 0.95 |
| VirusTotal | `VIRUSTOTAL_API_KEY` | 0.90 |
| PhishTank | `PHISHTANK_API_KEY` | 0.85 |
| OpenPhish | `OPENPHISH_API_KEY` | 0.85 |
| URLHaus (abuse.ch) | none | 0.85 |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 0.80 |
| URLScan.io | none (rate-limited) | 0.75 |
| AlienVault OTX | `OTX_API_KEY` | 0.70 |
| RDAP / WHOIS | none | 0.30 (informational) |

Plug-in contract: `async fn(httpx.AsyncClient, url) -> NormalizedProviderResult`.
Register in `providers.DEFAULT_PROVIDERS` or pass a custom dict to the
orchestrator to bypass the registry.

## 4. Provider Normalization

Every adapter returns:

```python
NormalizedProviderResult(
  provider, status,               # skipped|ok|timeout|error|unknown
  verdict,                        # safe|suspicious|malicious|unknown
  malicious, suspicious, safe,
  confidence,                     # 0.0–1.0
  threat_types, categories,
  detection_reason, reference_url,
  raw, latency_ms, error, timestamp,
)
```

## 5. Correlation Engine

`correlation.correlate(provider_results, indicators, has_urls, has_attachments)`
merges provider evidence and heuristic indicators into a single
`ThreatVerdict` with reasons and next-step recommendations.

## 6. Confidence Algorithm

```
weight_sum   = Σ reputation weight of providers reporting malicious/suspicious
weight_max   = Σ reputation weight of providers that returned ok
base         = weight_sum / weight_max
heur_boost   = min(0.25, 0.05 × indicator_count)
confidence   = min(1.0, base + heur_boost)
```

## 7. Threat Score Algorithm

```
score  = Σ (45 × w) for malicious providers
       + Σ (18 × w) for suspicious providers
       + Σ severity_points(indicator)   {low:5, medium:12, high:22, critical:35}
score  = min(100, score)

verdict  = malicious if score ≥ 65
         = suspicious if score ≥ 30
         = safe otherwise
severity = critical ≥85, high ≥65, medium ≥40, low ≥15, safe otherwise
```

## 8. Local Heuristic Engine

- URL: non-HTTPS, shortener, IP-in-URL, non-standard port, long/hyphen host,
  homograph, typosquat (Levenshtein ≤ 2 vs 20+ brand list), unicode
  confusables.
- Text: urgency, credential harvesting, BEC/wire fraud, inline base64 imagery.
- Attachment: executable extensions, macro-enabled office, double-extension,
  password-protected archive, MSDOS-executable MIME.
- Email auth: SPF/DKIM/DMARC fail/softfail/none/temp/perm error.

## 9. Domain Intelligence

RDAP adapter returns registration date; homograph/typosquat detection
in the heuristic engine complements provider domain reputation.

## 10. URL Intelligence

Combined provider verdicts (GSB, VT, URLScan, URLHaus, PhishTank, OpenPhish,
OTX) + heuristic URL indicators (transport, shortener, IP, port, hyphens).

## 11. Email Header Intelligence

`heuristics.analyze_email_auth(auth)` grades SPF/DKIM/DMARC results and
lifts failures into the indicator stream (feeds correlation & confidence).

## 12. Attachment Intelligence

Heuristic classifier flags executables, macro documents, double-extensions,
and password-protected archives at critical/high severity. Existing OCR /
attachment analyzers (Module 7) remain the primary content pipeline.

## 13. Redis Caching Strategy

- Namespace `ti:v1:*`.
- TTL 6h for malicious results; 30 min negative cache.
- Cache is best-effort: read/write failures never block analysis.

## 14. Celery Worker Architecture

Existing `threat.*` queue owns background threat scans. New orchestrator is
async-safe and can be invoked directly from workers or FastAPI routes.

## 15. Database Integration

The pipeline persists into the existing `threats` collection via
`services/phishing/pipeline.analyze_message` — no schema change.

## 16. API Design

Additive endpoints can wrap the orchestrator without altering existing
routes. Suggested (not yet wired) surface:

- `POST /api/v1/threat/analyze` — body `{ url? | urls? | text? | attachments? }`
- `GET /api/v1/threat/providers` — list of registered adapters + weights
- `GET /api/v1/threat/{id}` — fetch persisted verdict from `threats`

## 17. Logging

Latencies captured in `NormalizedProviderResult.latency_ms`. Errors are
attached, never swallowed silently. Correlation reasons are stored on the
final verdict for auditability.

## 18. Security

- API keys read via `app.core.config.settings` (env-only).
- Never logged.
- Providers isolated behind `try/except` so a compromised endpoint cannot
  crash the pipeline.

## 19. Testing

`app/tests/test_phase15_threat_intel.py` covers:
- Provider registry
- Heuristics (shortener, IP-URL, typosquat, exec attachment, double-ext,
  urgency+credential language, SPF/DMARC fail)
- Confidence rises with agreement
- Score & verdict for malicious multi-source case
- Safe verdict when no signals
- Orchestrator fan-out with mocked providers
- Timeout accounting

Run:

```bash
pytest app/tests/test_phase15_threat_intel.py -v
```

## 20. Production Deployment Recommendations

- Provision API keys via workspace secrets manager; do not commit `.env`.
- Enable Redis persistence to preserve cache across restarts.
- Alert on high `timeout`/`error` provider rates via Prometheus.
- Tune per-provider TIMEOUT via env if upstream SLOs drift.
- Add new providers by extending `DEFAULT_PROVIDERS` and giving them a
  reputation weight — no orchestrator changes required.

**Status: READY — additive, backward compatible.**
