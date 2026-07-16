"""DNS + SSL probe provider.

Not a third-party API — this provider makes native DNS lookups and an
SSL handshake to gather signals the aggregator uses (MX presence, TLS
validity, self-signed leaf, expiry). Kept behind the same
`BaseProvider` interface so telemetry / caching / circuit-breaker apply
uniformly.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.services.threat.normalizer import registered_domain
from app.services.threat.providers.base import (
    ArtifactKind,
    BaseProvider,
    ProviderOutcome,
)


async def _resolve(hostname: str, family: int, port: int = 443) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, port, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def _mx_lookup(domain: str) -> list[str]:
    # dnspython optional; use a resolver only when installed. Kept sync
    # inside a run_in_executor call to avoid blocking the loop.
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=3.0)
        return sorted(str(a.exchange).rstrip(".") for a in answers)
    except Exception:
        return []


def _probe_ssl(host: str, port: int = 443) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
    except ssl.SSLError as e:
        return {"valid": False, "error": str(e)[:200]}
    except (OSError, socket.timeout) as e:
        return {"valid": False, "error": type(e).__name__}
    not_after = cert.get("notAfter")
    expires_at = None
    days_left = None
    if not_after:
        try:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = int((expires_at - datetime.now(timezone.utc)).days)
        except ValueError:
            pass
    issuer = "/".join("=".join(x) for pair in cert.get("issuer", []) for x in pair)
    subject = "/".join("=".join(x) for pair in cert.get("subject", []) for x in pair)
    self_signed = subject == issuer
    return {
        "valid": True,
        "issuer": issuer,
        "subject": subject,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "self_signed": self_signed,
    }


class DnsSslProvider(BaseProvider):
    slug = "dns_ssl"
    kinds = ("url", "domain")

    async def _call(
        self, client: httpx.AsyncClient, artifact_kind: ArtifactKind, artifact_value: str
    ) -> ProviderOutcome:
        host = artifact_value
        if artifact_kind == "url":
            host = urlparse(artifact_value).hostname or ""
        if not host:
            return ProviderOutcome(self.slug, artifact_kind, artifact_value, status="error",
                                   error_code="no_host")
        v4 = await _resolve(host, socket.AF_INET)
        v6 = await _resolve(host, socket.AF_INET6)
        loop = asyncio.get_running_loop()
        mx = await loop.run_in_executor(None, _mx_lookup, registered_domain(host) or host)
        ssl_info = await loop.run_in_executor(None, _probe_ssl, host)
        # Verdict here is always "unknown" — this provider produces
        # facts, not judgements. The aggregator translates facts to
        # scores.
        return ProviderOutcome(
            provider=self.slug,
            artifact_kind=artifact_kind,
            artifact_value=artifact_value,
            status="ok",
            verdict="unknown",
            normalized_score=0.0,
            raw={
                "host": host,
                "ipv4": v4,
                "ipv6": v6,
                "mx": mx,
                "ssl": ssl_info,
            },
        )
