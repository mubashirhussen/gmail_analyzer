"""IP → coarse location lookup (best-effort, non-blocking, fail-open)."""
from __future__ import annotations

import structlog

from app.core.http import get_client

log = structlog.get_logger(__name__)


async def coarse_location(ip: str) -> str:
    if not ip or ip.startswith(("127.", "10.", "192.168.", "::1")):
        return "local"
    try:
        r = await get_client().get(f"https://ipapi.co/{ip}/json/", timeout=3.0)
        if r.status_code != 200:
            return ""
        d = r.json()
        city, cc = d.get("city") or "", d.get("country_code") or ""
        return ", ".join(x for x in (city, cc) if x)
    except Exception as e:  # noqa: BLE001
        log.debug("geoip_failed", ip=ip, err=str(e))
        return ""
