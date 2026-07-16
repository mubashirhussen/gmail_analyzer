"""HeaderParserService — normalise RFC-5322 headers for security analysis.

Gmail returns headers as a list of ``{name, value}`` pairs. We extract only
the fields relevant to phishing/impersonation detection and store them in
a strongly-typed ``ParsedHeaders``.
"""
from __future__ import annotations

import re
from typing import Iterable

from app.models.email import ParsedHeaders

_AUTH_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)


def _find(headers: Iterable[dict], name: str) -> str | None:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


def _find_all(headers: Iterable[dict], name: str) -> list[str]:
    return [h["value"] for h in headers if h.get("name", "").lower() == name.lower()]


class HeaderParserService:
    def parse(self, headers: list[dict]) -> ParsedHeaders:
        auth = _find(headers, "Authentication-Results") or ""
        spf = dkim = dmarc = None
        for match in _AUTH_RE.finditer(auth):
            kind, verdict = match.group(1).lower(), match.group(2).lower()
            if kind == "spf":
                spf = verdict
            elif kind == "dkim":
                dkim = verdict
            elif kind == "dmarc":
                dmarc = verdict
        return ParsedHeaders(
            message_id=_find(headers, "Message-ID"),
            return_path=_find(headers, "Return-Path"),
            reply_to=_find(headers, "Reply-To"),
            received=_find_all(headers, "Received")[:20],
            authentication_results=auth or None,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            x_originating_ip=_find(headers, "X-Originating-IP"),
            user_agent=_find(headers, "User-Agent"),
            mailer=_find(headers, "X-Mailer") or _find(headers, "Mailer"),
            content_type=_find(headers, "Content-Type"),
            list_unsubscribe=_find(headers, "List-Unsubscribe"),
        )


header_parser_service = HeaderParserService()
