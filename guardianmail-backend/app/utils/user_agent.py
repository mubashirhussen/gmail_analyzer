"""User-Agent parsing (browser/OS/device type) with no external dependency.

Small heuristic parser — good enough for display + risk fingerprinting.
Swap for `ua-parser` if higher fidelity is ever needed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class UAInfo:
    browser: str = "Unknown"
    os: str = "Unknown"
    device_type: str = "desktop"


_BROWSERS = [
    ("Edg/", "Edge"), ("OPR/", "Opera"), ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"), ("Safari/", "Safari"),
]
_OS = [
    ("Windows NT 10", "Windows 10/11"), ("Windows NT", "Windows"),
    ("Mac OS X", "macOS"), ("Android", "Android"), ("iPhone", "iOS"),
    ("iPad", "iPadOS"), ("Linux", "Linux"),
]
_MOBILE = re.compile(r"Mobile|Android|iPhone", re.I)
_TABLET = re.compile(r"iPad|Tablet", re.I)
_BOT = re.compile(r"bot|crawler|spider|python-requests|curl|wget", re.I)


def parse(ua: str) -> UAInfo:
    if not ua:
        return UAInfo()
    info = UAInfo()
    for tag, name in _BROWSERS:
        if tag in ua:
            info.browser = name
            break
    for tag, name in _OS:
        if tag in ua:
            info.os = name
            break
    if _BOT.search(ua):
        info.device_type = "bot"
    elif _TABLET.search(ua):
        info.device_type = "tablet"
    elif _MOBILE.search(ua):
        info.device_type = "mobile"
    return info
