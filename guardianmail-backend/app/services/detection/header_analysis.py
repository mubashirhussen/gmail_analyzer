"""HeaderAnalysisService — SPF/DKIM/DMARC/ARC + received-chain anomalies."""
from __future__ import annotations

import re
from typing import Any


_AUTH_PASS = {"pass"}
_AUTH_FAIL = {"fail", "softfail", "hardfail", "permerror"}


def _auth_value(headers: dict[str, Any], key: str) -> str:
    v = headers.get(key) or headers.get(key.lower()) or headers.get(key.upper())
    if isinstance(v, dict):
        v = v.get("result") or v.get("value") or ""
    return str(v or "").strip().lower()


def _extract_auth_results(headers: dict[str, Any]) -> dict[str, str]:
    """Parse Authentication-Results header if present."""
    raw = headers.get("Authentication-Results") or headers.get("authentication-results") or ""
    out: dict[str, str] = {}
    if isinstance(raw, str):
        for mech in ("spf", "dkim", "dmarc", "arc"):
            m = re.search(rf"{mech}=([a-z]+)", raw, re.I)
            if m:
                out[mech] = m.group(1).lower()
    return out


class HeaderAnalysisService:
    def analyze(self, headers: dict[str, Any] | None) -> dict[str, Any]:
        headers = headers or {}
        parsed = _extract_auth_results(headers)
        spf = parsed.get("spf") or _auth_value(headers, "spf")
        dkim = parsed.get("dkim") or _auth_value(headers, "dkim")
        dmarc = parsed.get("dmarc") or _auth_value(headers, "dmarc")
        arc = parsed.get("arc") or _auth_value(headers, "arc")

        anomalies: list[str] = []
        score = 0.0

        for k, v in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc)):
            if v in _AUTH_FAIL:
                anomalies.append(f"{k}_fail")
                score += 20 if k == "dmarc" else 12
            elif v and v not in _AUTH_PASS and v != "none":
                anomalies.append(f"{k}_{v}")
                score += 5

        reply_to = str(headers.get("Reply-To") or "").lower()
        from_addr = str(headers.get("From") or "").lower()
        return_path = str(headers.get("Return-Path") or "").lower()

        if reply_to and from_addr and _domain(reply_to) and _domain(from_addr) \
                and _domain(reply_to) != _domain(from_addr):
            anomalies.append("reply_to_domain_mismatch")
            score += 15

        if return_path and from_addr and _domain(return_path) and _domain(from_addr) \
                and _domain(return_path) != _domain(from_addr):
            anomalies.append("return_path_mismatch")
            score += 10

        received = headers.get("Received") or []
        if isinstance(received, str):
            received = [received]
        if isinstance(received, list) and len(received) > 12:
            anomalies.append("long_received_chain")
            score += 5

        return {
            "spf": spf or "unknown",
            "dkim": dkim or "unknown",
            "dmarc": dmarc or "unknown",
            "arc": arc or "unknown",
            "anomalies": anomalies,
            "score": min(60.0, score),
        }


def _domain(addr: str) -> str:
    m = re.search(r"@([\w\.-]+)", addr or "")
    return m.group(1).lower() if m else ""


header_analysis_service = HeaderAnalysisService()
