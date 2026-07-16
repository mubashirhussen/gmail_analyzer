"""Phase 15 — Enterprise threat-intel platform.

Additive, non-invasive layer on top of the existing url_scan/scoring stack.
Provides:

* A pluggable provider registry (`providers`)
* A parallel orchestrator with per-provider timeout + graceful degradation
* Normalization to a unified `NormalizedProviderResult` shape
* Correlation, confidence, and 0–100 threat score engines
* Local heuristic engine (typosquat, homograph, shorteners, urgency, etc.)

Existing services (`services/url_scan/scanner.scan_urls`, `services/scoring/*`)
are unchanged — the orchestrator wraps them.
"""
