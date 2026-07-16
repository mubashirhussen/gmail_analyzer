"""Canonicalization utilities for URLs, domains, IPs, and hashes.

Every artefact the engine analyses is first passed through here so that
downstream cache lookups, provider calls, and IOC de-duplication agree
on a single canonical form.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from urllib.parse import quote, unquote, urlparse, urlunparse

import idna
import tldextract

_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "mc_cid", "mc_eid", "_hsenc", "_hsmi",
}

_URL_RE = re.compile(
    r"""\b((?:https?|ftp)://[^\s<>"']+|(?:www\.)[^\s<>"']+)""",
    re.IGNORECASE,
)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------- URLs
def normalize_url(raw: str) -> str | None:
    """Return a canonical URL or None if it cannot be parsed.

    Steps:
    * strip surrounding punctuation & control chars
    * add scheme if missing
    * lowercase host, punycode IDN, drop default port
    * remove fragment, sort query, drop tracking params
    """
    if not raw:
        return None
    raw = raw.strip().strip(".,;:)]}>'\"")
    if not raw:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
    except ValueError:
        return None
    if not p.netloc:
        return None
    host = p.hostname or ""
    host = host.lower().rstrip(".")
    if not host:
        return None
    try:
        # Encode IDN → punycode so provider APIs receive ASCII.
        host_ascii = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        host_ascii = host
    port = ""
    if p.port and not ((p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443)):
        port = f":{p.port}"
    userinfo = ""
    if p.username:
        userinfo = quote(p.username, safe="")
        if p.password:
            userinfo += ":" + quote(p.password, safe="")
        userinfo += "@"
    # Query hygiene: drop tracking, keep order-stable.
    kept: list[str] = []
    for pair in p.query.split("&"):
        if not pair:
            continue
        k = pair.split("=", 1)[0].lower()
        if k in _TRACKING_PARAMS:
            continue
        kept.append(pair)
    query = "&".join(sorted(kept))
    path = re.sub(r"/{2,}", "/", p.path) or "/"
    try:
        path = quote(unquote(path), safe="/%:@!$&'()*+,;=~-._")
    except Exception:  # pragma: no cover - defensive
        pass
    return urlunparse((p.scheme.lower(), userinfo + host_ascii + port, path, "", query, ""))


def extract_urls(text: str, *, limit: int = 100) -> list[str]:
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _URL_RE.finditer(text):
        u = normalize_url(m.group(1))
        if u and u not in seen:
            seen.add(u)
            out.append(u)
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------- domains
def registered_domain(host_or_url: str) -> str | None:
    if not host_or_url:
        return None
    ext = tldextract.extract(host_or_url)
    if not ext.suffix or not ext.domain:
        return None
    return f"{ext.domain}.{ext.suffix}".lower()


def tld_of(host_or_url: str) -> str | None:
    ext = tldextract.extract(host_or_url or "")
    return ext.suffix.lower().split(".")[-1] if ext.suffix else None


def subdomain_of(host_or_url: str) -> str | None:
    ext = tldextract.extract(host_or_url or "")
    return ext.subdomain.lower() or None


def is_idn(host: str) -> bool:
    if not host:
        return False
    return host.startswith("xn--") or any(part.startswith("xn--") for part in host.split("."))


def contains_mixed_scripts(host: str) -> bool:
    """Cheap Unicode homograph heuristic."""
    scripts: set[str] = set()
    for ch in host:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        # Bucket by leading script word.
        scripts.add(name.split(" ", 1)[0])
        if len(scripts) > 1:
            return True
    return False


# --------------------------------------------------------------------- IPs
def normalize_ip(raw: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except (ValueError, AttributeError):
        return None


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ------------------------------------------------------------------ emails
_EMAIL_RE = re.compile(r"([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)


def normalize_email(raw: str) -> str | None:
    if not raw:
        return None
    m = _EMAIL_RE.search(raw)
    if not m:
        return None
    local, host = m.group(1), m.group(2).lower().rstrip(".")
    return f"{local}@{host}"


def domain_of_email(addr: str) -> str | None:
    n = normalize_email(addr)
    return n.split("@", 1)[1] if n else None
