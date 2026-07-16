"""Email authentication analysis — SPF, DKIM, DMARC + identity mismatches.

Reads:
* `Authentication-Results` (RFC 8601) as the primary source.
* `Received-SPF`, `DKIM-Signature`, `From`, `Reply-To`, `Return-Path`
  as corroborating headers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.services.threat.normalizer import domain_of_email


@dataclass(slots=True)
class AuthIndicator:
    category: str
    severity: str
    detail: str
    evidence: dict


_AR_RE = re.compile(r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|permerror|temperror|none)\b", re.IGNORECASE)


def _get(headers: Iterable[dict], name: str) -> list[str]:
    n = name.lower()
    return [h.get("value", "") for h in headers if h.get("name", "").lower() == n]


class AuthenticationAnalysisService:
    def analyze(self, headers: list[dict]) -> tuple[dict[str, str], list[AuthIndicator]]:
        out: list[AuthIndicator] = []
        results: dict[str, str] = {"spf": "none", "dkim": "none", "dmarc": "none"}

        for line in _get(headers, "Authentication-Results"):
            for m in _AR_RE.finditer(line):
                results[m.group(1).lower()] = m.group(2).lower()

        # SPF fallback from Received-SPF
        if results["spf"] == "none":
            rspf = next(iter(_get(headers, "Received-SPF")), "").lower()
            for keyword in ("pass", "fail", "softfail", "neutral", "permerror", "temperror"):
                if rspf.startswith(keyword):
                    results["spf"] = keyword
                    break

        if results["spf"] == "fail":
            out.append(AuthIndicator("spf_fail", "high", "SPF authentication failed — sender IP not authorized.", {"spf": results["spf"]}))
        elif results["spf"] in ("softfail", "neutral"):
            out.append(AuthIndicator("spf_soft", "low", f"SPF is {results['spf']} — sender alignment is weak.", {"spf": results["spf"]}))
        elif results["spf"] == "none":
            out.append(AuthIndicator("spf_missing", "low", "No SPF result recorded.", {}))

        if results["dkim"] == "fail":
            out.append(AuthIndicator("dkim_fail", "high", "DKIM signature did not verify.", {"dkim": results["dkim"]}))
        elif results["dkim"] == "none":
            out.append(AuthIndicator("dkim_missing", "low", "Message is not DKIM-signed.", {}))

        if results["dmarc"] == "fail":
            out.append(AuthIndicator("dmarc_fail", "high", "DMARC evaluation failed for this message.", {"dmarc": results["dmarc"]}))
        elif results["dmarc"] == "none":
            out.append(AuthIndicator("dmarc_missing", "medium", "Sending domain has no enforced DMARC policy.", {}))

        # ---- identity mismatches ------------------------------------------
        from_hdr = next(iter(_get(headers, "From")), "")
        reply_to = next(iter(_get(headers, "Reply-To")), "")
        return_path = next(iter(_get(headers, "Return-Path")), "")
        envelope_from = next(iter(_get(headers, "X-Envelope-From")), "")

        from_dom = domain_of_email(from_hdr)
        rt_dom = domain_of_email(reply_to)
        rp_dom = domain_of_email(return_path)
        env_dom = domain_of_email(envelope_from)

        if from_dom and rt_dom and rt_dom != from_dom:
            out.append(AuthIndicator(
                "reply_to_mismatch", "high",
                f"Reply-To domain '{rt_dom}' does not match From domain '{from_dom}'.",
                {"from": from_dom, "reply_to": rt_dom},
            ))
        if from_dom and rp_dom and rp_dom != from_dom:
            out.append(AuthIndicator(
                "return_path_mismatch", "medium",
                f"Return-Path domain '{rp_dom}' differs from From domain '{from_dom}'.",
                {"from": from_dom, "return_path": rp_dom},
            ))
        if from_dom and env_dom and env_dom != from_dom:
            out.append(AuthIndicator(
                "envelope_mismatch", "medium",
                f"Envelope sender '{env_dom}' differs from From domain '{from_dom}'.",
                {"from": from_dom, "envelope": env_dom},
            ))
        # Display-name vs address (e.g. "Chase Support <attacker@evil.tk>")
        if from_hdr and "<" in from_hdr and ">" in from_hdr:
            display = from_hdr.split("<", 1)[0].strip().strip('"').lower()
            if display and from_dom and display and display.replace(" ", "") not in from_dom:
                # Only flag when display *contains* a domain-looking token that mismatches.
                if any(brand in display for brand in ("bank", "paypal", "microsoft", "google", "apple", "amazon")):
                    out.append(AuthIndicator(
                        "display_name_mismatch", "high",
                        f"Display name '{display}' impersonates a brand but sender domain is '{from_dom}'.",
                        {"display": display, "from": from_dom},
                    ))
        return results, out


authentication_analysis_service = AuthenticationAnalysisService()
