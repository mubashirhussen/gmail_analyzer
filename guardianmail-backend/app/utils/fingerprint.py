"""Device fingerprint helpers.

The client sends a stable browser-derived fingerprint. We combine it with
IP-network prefix + UA family to produce a server-side hash used for
"unknown device" detection. Two devices with identical client fingerprint
but very different IP subnets score as different.
"""
from __future__ import annotations

import hashlib


def _ip_prefix(ip: str) -> str:
    if not ip:
        return ""
    if ":" in ip:                                       # ipv6
        return ":".join(ip.split(":")[:4])
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else ip


def compose(client_fp: str, ip: str, ua_family: str) -> str:
    h = hashlib.sha256()
    for part in (client_fp.strip().lower(), _ip_prefix(ip), ua_family.lower()):
        h.update(part.encode())
        h.update(b"\x1f")
    return h.hexdigest()
