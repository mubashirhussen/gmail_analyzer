"""EmailMetadataService — turn a Gmail message payload into an ``EmailDoc``.

Delegates header parsing, URL extraction, and attachment metadata to their
respective services so this module stays focused on assembly.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr
from typing import Any

from app.models.email import EmailDoc
from app.services.gmail.attachment_metadata_service import attachment_metadata_service
from app.services.gmail.headers_service import header_parser_service
from app.services.gmail.url_extraction_service import url_extraction_service


CATEGORY_LABELS = {"CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS",
                   "CATEGORY_UPDATES", "CATEGORY_FORUMS"}


def _addr_list(raw: str) -> list[str]:
    if not raw:
        return []
    return [addr for _, addr in getaddresses([raw]) if addr]


def _domain_of(addr: str) -> str | None:
    if not addr or "@" not in addr:
        return None
    return addr.rsplit("@", 1)[-1].lower().strip()


def _b64url_decode(data: str) -> str:
    try:
        return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _walk_body(payload: dict[str, Any]) -> tuple[str, str]:
    """Return (text, html) collected from all parts."""
    text_buf: list[str] = []
    html_buf: list[str] = []

    def rec(part: dict[str, Any]) -> None:
        mime = (part.get("mimeType") or "").lower()
        body = part.get("body") or {}
        data = body.get("data")
        if data:
            if mime == "text/plain":
                text_buf.append(_b64url_decode(data))
            elif mime == "text/html":
                html_buf.append(_b64url_decode(data))
        for child in part.get("parts") or []:
            rec(child)

    rec(payload or {})
    return "".join(text_buf), "".join(html_buf)


class EmailMetadataService:
    def build(
        self,
        *,
        user_id: str,
        connection_id: str,
        msg: dict[str, Any],
        keep_body: bool = False,
    ) -> EmailDoc:
        payload = msg.get("payload") or {}
        headers = payload.get("headers") or []

        def h(name: str) -> str:
            for entry in headers:
                if entry.get("name", "").lower() == name.lower():
                    return entry.get("value", "")
            return ""

        sender_raw = h("From")
        sender_name, sender_email = parseaddr(sender_raw)
        sender_domain = _domain_of(sender_email)

        text, html = _walk_body(payload)
        parsed_headers = header_parser_service.parse(headers)
        urls = url_extraction_service.extract(text=text, html=html)
        attachments = attachment_metadata_service.extract(payload)

        labels = msg.get("labelIds") or []
        categories = [l for l in labels if l in CATEGORY_LABELS]

        received_ms = int(msg.get("internalDate") or 0)
        received_at = datetime.fromtimestamp(received_ms / 1000, tz=timezone.utc) \
            if received_ms else datetime.now(tz=timezone.utc)

        # Body storage policy: only retain when caller explicitly requests it
        # (forwarded / deep-scan). Otherwise we keep just the Gmail snippet.
        body_text = text[:200_000] if keep_body else ""
        body_html = (html[:400_000] if keep_body else None) or None

        return EmailDoc(
            user_id=user_id,
            connection_id=connection_id,
            gmail_id=msg.get("id"),
            thread_id=msg.get("threadId"),
            history_id=str(msg.get("historyId")) if msg.get("historyId") else None,
            sender=sender_raw,
            sender_name=sender_name or None,
            sender_email=sender_email or None,
            sender_domain=sender_domain,
            reply_to=parseaddr(h("Reply-To"))[1] or None,
            recipients=_addr_list(h("To")),
            cc=_addr_list(h("Cc")),
            bcc=_addr_list(h("Bcc")),
            subject=h("Subject"),
            snippet=(msg.get("snippet") or "")[:2_000],
            body_text=body_text,
            body_html=body_html,
            full_body_retained=keep_body,
            labels=labels,
            label_names=[],  # resolved by LabelService when caller requests
            is_unread="UNREAD" in labels,
            is_starred="STARRED" in labels,
            is_important="IMPORTANT" in labels,
            categories=categories,
            mime_type=payload.get("mimeType"),
            size_estimate=int(msg.get("sizeEstimate") or 0),
            headers=parsed_headers,
            urls=urls,
            has_attachments=bool(attachments),
            attachments=attachments,
            received_at=received_at,
            analysis_status="pending",
        )


email_metadata_service = EmailMetadataService()
