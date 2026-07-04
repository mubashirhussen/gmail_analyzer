"""SPF / DKIM / DMARC lookups for a sender domain (best-effort, DNS only)."""
from __future__ import annotations

import re

import dns.resolver

_EMAIL_RE = re.compile(r"[^@\s]+@([A-Za-z0-9.-]+)")


async def spf_dkim_dmarc(sender: str) -> dict:
    m = _EMAIL_RE.search(sender or "")
    if not m:
        return {"domain": None, "spf": None, "dmarc": None}
    domain = m.group(1).lower()

    def _txt(name: str) -> str | None:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=3.0)
            for a in answers:
                s = b"".join(a.strings).decode(errors="ignore")
                if "v=spf1" in s or "v=DMARC1" in s:
                    return s
            return None
        except Exception:
            return None

    return {
        "domain": domain,
        "spf": _txt(domain),
        "dmarc": _txt(f"_dmarc.{domain}"),
    }
