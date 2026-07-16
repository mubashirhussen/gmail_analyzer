"""UrlExtractionService — pulls, normalises, and deduplicates URLs.

Sources handled:
* plain-text bodies (regex over token boundaries),
* HTML bodies (anchor href + form action + srcset first URL + img src).

Downstream QR/image URL extraction lives in the OCR module — not here.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from app.models.email import UrlRef

_URL_RE = re.compile(
    r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE
)


def _normalise(raw: str) -> UrlRef | None:
    raw = raw.strip().rstrip(".,);]}>")
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    normalized = urlunsplit((scheme, host + (f":{parts.port}" if parts.port else ""),
                              parts.path or "/", parts.query or "", ""))
    labels = host.split(".")
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else None
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return UrlRef(
        raw=raw,
        normalized=normalized,
        scheme=scheme,
        domain=domain,
        subdomain=subdomain,
        path=parts.path or None,
        query=parts.query or None,
        source="text",
    )


class _HrefCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hits: list[tuple[str, str]] = []  # (url, source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hits.append((a["href"], "button"))
        elif tag == "img" and a.get("src"):
            self.hits.append((a["src"], "image"))
        elif tag == "form" and a.get("action"):
            self.hits.append((a["action"], "button"))


class UrlExtractionService:
    def extract(self, *, text: str | None, html: str | None) -> list[UrlRef]:
        buckets: dict[str, UrlRef] = {}

        def _add(candidate: str, source: str) -> None:
            ref = _normalise(candidate)
            if not ref:
                return
            ref.source = source  # type: ignore[assignment]
            buckets.setdefault(ref.normalized, ref)

        if text:
            for match in _URL_RE.findall(text)[:500]:
                _add(match, "text")
        if html:
            parser = _HrefCollector()
            try:
                parser.feed(html)
            except Exception:  # noqa: BLE001
                pass
            for candidate, source in parser.hits[:500]:
                _add(candidate, source)
            # fall back: raw regex over html too, in case attributes are malformed
            for match in _URL_RE.findall(html)[:500]:
                _add(match, "html")

        return list(buckets.values())[:500]


url_extraction_service = UrlExtractionService()
