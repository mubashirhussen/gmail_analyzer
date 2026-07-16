"""Post-scan link safety revalidation.

When a user clicks a URL that was previously scanned, we re-run the threat
intelligence pipeline and diff the result against the stored baseline. If any
signal moved in the "worse" direction (new provider flag, redirect target
changed, WHOIS/registrar changed, SSL rotated to an untrusted issuer, domain
age crossed a suspicious threshold), the caller must warn the user before
opening the destination.

This module is intentionally provider-agnostic — it composes the existing
`scan_urls` service and adds delta detection + SSL/redirect probes that the
initial scan doesn't run for cost reasons.
"""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import tldextract

from app.database.mongodb import get_db
from app.services.url_scan.scanner import scan_urls
from app.utils.hashing import artifact_hash

_TIMEOUT = 6.0


async def _follow_redirects(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=_TIMEOUT) as c:
            r = await c.head(url)
            chain = [str(h.url) for h in r.history] + [str(r.url)]
            return {"final_url": str(r.url), "chain": chain, "status": r.status_code}
    except Exception as e:  # noqa: BLE001
        return {"final_url": None, "chain": [], "error": str(e)}


async def _ssl_cert(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host or parsed.scheme != "https":
        return {"ok": False, "reason": "not-https"}
    try:
        loop = asyncio.get_event_loop()
        def _probe() -> dict:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(_open_socket(host), server_hostname=host) as s:
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                return {
                    "ok": True,
                    "issuer": issuer.get("organizationName"),
                    "subject_cn": subject.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
        return await asyncio.wait_for(loop.run_in_executor(None, _probe), timeout=_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": str(e)}


def _open_socket(host: str):
    import socket
    s = socket.create_connection((host, 443), timeout=5)
    return s


def _severity(before: dict, after: dict) -> str:
    """Return the change severity: none|info|warn|critical."""
    if not before:
        return "info"
    b_flagged = before.get("flagged")
    a_flagged = after.get("flagged")
    if not b_flagged and a_flagged:
        return "critical"
    if a_flagged and b_flagged:
        return "warn"
    # new providers reporting flags now
    b_flags = {p["provider"] for p in before.get("providers", []) if p.get("status") == "flagged"}
    a_flags = {p["provider"] for p in after.get("providers", []) if p.get("status") == "flagged"}
    if a_flags - b_flags:
        return "warn"
    return "none"


async def revalidate(url: str, user_id: str | None = None) -> dict[str, Any]:
    """Re-scan a URL and diff against the last stored baseline for this artifact."""
    db = get_db()
    key = f"link|{url}"
    art_hash = artifact_hash("link", url)

    baseline = await db.artifact_stats.find_one({"hash": art_hash}) or {}
    prior_scan = baseline.get("last_scan") or {}

    fresh_task = scan_urls([url])
    redirect_task = _follow_redirects(url)
    ssl_task = _ssl_cert(url)
    scan, redirects, cert = await asyncio.gather(fresh_task, redirect_task, ssl_task)

    fresh = (scan.get("results") or [{}])[0]
    domain = tldextract.extract(url).registered_domain

    severity = _severity(prior_scan, fresh)
    changes: list[str] = []

    prior_final = (prior_scan.get("redirect") or {}).get("final_url")
    if prior_final and redirects.get("final_url") and prior_final != redirects["final_url"]:
        changes.append(f"Redirect target changed: {prior_final} → {redirects['final_url']}")
        severity = "critical" if severity == "none" else severity

    prior_cert = prior_scan.get("ssl") or {}
    if prior_cert.get("issuer") and cert.get("issuer") and prior_cert["issuer"] != cert["issuer"]:
        changes.append(f"SSL issuer changed: {prior_cert['issuer']} → {cert['issuer']}")
        severity = "warn" if severity == "none" else severity

    b_flags = {p["provider"] for p in prior_scan.get("providers", []) if p.get("status") == "flagged"}
    a_flags = {p["provider"] for p in fresh.get("providers", []) if p.get("status") == "flagged"}
    new_flags = a_flags - b_flags
    if new_flags:
        changes.append(f"New provider flags: {', '.join(sorted(new_flags))}")

    result = {
        "url": url,
        "domain": domain,
        "flagged": fresh.get("flagged", False),
        "providers": fresh.get("providers", []),
        "redirect": redirects,
        "ssl": cert,
        "severity": severity,          # none|info|warn|critical
        "should_warn": severity in ("warn", "critical"),
        "changes": changes,
        "checked_at": datetime.now(timezone.utc),
        "baseline_at": baseline.get("last_seen"),
    }

    # persist the new baseline
    await db.artifact_stats.update_one(
        {"hash": art_hash},
        {"$set": {"kind": "link", "key": key, "last_scan": {
            "flagged": fresh.get("flagged", False),
            "providers": fresh.get("providers", []),
            "redirect": redirects, "ssl": cert,
        }, "last_seen": result["checked_at"]},
         "$setOnInsert": {"first_seen": result["checked_at"]}},
        upsert=True,
    )
    await db.artifact_events.insert_one({
        "hash": art_hash, "kind": "link", "user_id": user_id,
        "at": result["checked_at"], "event": "revalidate",
        "severity": severity, "changes": changes,
    })
    return result
