"""Header analysis.

Inspects the raw MIME headers (as delivered by Gmail metadata sync) and
flags structural anomalies: forged Received chains, absurd timestamps,
missing originating IP, X-Mailer red flags, etc.

Header values live on `EmailDoc.headers` as a list of {name, value}
tuples. Names are compared case-insensitively.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable


@dataclass(slots=True)
class HeaderIndicator:
    category: str
    severity: str
    detail: str
    evidence: dict


_IP_RE = re.compile(r"\[(?:\d{1,3}\.){3}\d{1,3}\]|\[(?:[0-9a-fA-F:]+)\]")
_MAX_RECEIVED_HOPS = 25
_MAX_CLOCK_SKEW = timedelta(minutes=30)
_SUSPECT_MAILERS = {"mass mailer", "phpmailer 5", "the bat!"}


def _get(headers: Iterable[dict], name: str) -> list[str]:
    n = name.lower()
    return [h.get("value", "") for h in headers if (h.get("name", "").lower() == n)]


class HeaderAnalysisService:
    def analyze(self, headers: list[dict], sent_at: datetime | None = None) -> list[HeaderIndicator]:
        out: list[HeaderIndicator] = []
        received = _get(headers, "Received")

        # -------- hop count -------------------------------------------------
        if len(received) > _MAX_RECEIVED_HOPS:
            out.append(HeaderIndicator(
                "forged_received", "medium",
                f"Received chain has {len(received)} hops — unusually deep.",
                {"hops": len(received)},
            ))

        # -------- originating IP -------------------------------------------
        origin_ip = None
        if received:
            m = _IP_RE.search(received[-1])
            origin_ip = m.group(0).strip("[]") if m else None
        if not origin_ip:
            out.append(HeaderIndicator(
                "missing_origin_ip", "low",
                "Could not determine originating IP from Received chain.",
                {"received_count": len(received)},
            ))

        # -------- timestamp skew -------------------------------------------
        date_hdr = next(iter(_get(headers, "Date")), "")
        parsed_date = None
        try:
            parsed_date = parsedate_to_datetime(date_hdr) if date_hdr else None
        except (TypeError, ValueError):
            parsed_date = None
        if parsed_date and sent_at:
            if abs(parsed_date - sent_at) > _MAX_CLOCK_SKEW:
                out.append(HeaderIndicator(
                    "timestamp_skew", "low",
                    "Message Date header disagrees with delivery time by >30 minutes.",
                    {"date_header": date_hdr, "delivered_at": sent_at.isoformat()},
                ))
        if parsed_date and parsed_date > datetime.now(timezone.utc) + _MAX_CLOCK_SKEW:
            out.append(HeaderIndicator(
                "future_timestamp", "medium",
                "Date header is in the future — likely forged.",
                {"date_header": date_hdr},
            ))

        # -------- x-mailer red flags ----------------------------------------
        mailer = next(iter(_get(headers, "X-Mailer")), "").lower()
        if mailer and any(s in mailer for s in _SUSPECT_MAILERS):
            out.append(HeaderIndicator(
                "suspicious_mailer", "medium",
                f"X-Mailer '{mailer}' is commonly used by bulk phishing kits.",
                {"x_mailer": mailer},
            ))

        # -------- missing message-id ---------------------------------------
        if not _get(headers, "Message-ID"):
            out.append(HeaderIndicator(
                "missing_message_id", "low",
                "Message-ID header is missing.",
                {},
            ))
        return out

    def extract_origin_ip(self, headers: list[dict]) -> str | None:
        for h in reversed(_get(headers, "Received") or []):
            m = _IP_RE.search(h)
            if m:
                return m.group(0).strip("[]")
        return None


header_analysis_service = HeaderAnalysisService()
