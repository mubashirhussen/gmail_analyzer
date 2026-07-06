"""Gmail sync — pulls messages, normalises headers/body, saves email docs,
then fans out an `threat.analyze_email` task per new message.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

from app.database.mongodb import get_db
from app.services.gmail.client import gmail_service, list_messages, get_message


def _header(headers: list[dict], name: str) -> str:
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""


def _walk_parts(payload: dict) -> tuple[str, str, list[dict]]:
    text, html, atts = "", "", []
    def rec(p: dict):
        nonlocal text, html
        mime = p.get("mimeType", "")
        body = p.get("body", {}) or {}
        data = body.get("data")
        if mime == "text/plain" and data:
            text += base64.urlsafe_b64decode(data + "==").decode(errors="replace")
        elif mime == "text/html" and data:
            html += base64.urlsafe_b64decode(data + "==").decode(errors="replace")
        elif body.get("attachmentId"):
            atts.append({"name": p.get("filename"), "mime": mime,
                         "size": body.get("size", 0), "attachment_id": body["attachmentId"]})
        for c in p.get("parts") or []:
            rec(c)
    rec(payload or {})
    return text, html, atts


async def sync_user(user_id: str) -> dict[str, Any]:
    db = get_db()
    user = await db.users.find_one({"_id": user_id})
    if not user or not user.get("gmail_refresh_encrypted"):
        return {"user_id": user_id, "processed": 0, "reason": "no_gmail_link"}

    service = gmail_service(user["gmail_refresh_encrypted"])
    since = user.get("gmail_last_cursor") or "newer_than:7d"
    processed = 0
    new_ids: list[str] = []

    for meta in list_messages(service, query=since, max_results=100):
        gid = meta["id"]
        if await db.emails.find_one({"gmail_id": gid}, {"_id": 1}):
            continue
        msg = get_message(service, gid)
        headers = msg.get("payload", {}).get("headers", [])
        text, html, atts = _walk_parts(msg.get("payload", {}))
        doc = {
            "user_id": user_id,
            "gmail_id": gid,
            "thread_id": msg.get("threadId"),
            "sender": _header(headers, "From"),
            "recipients": [_header(headers, "To")],
            "subject": _header(headers, "Subject"),
            "snippet": msg.get("snippet", ""),
            "body_text": text[:200_000],
            "body_html": html[:400_000] or None,
            "labels": msg.get("labelIds", []),
            "has_attachments": bool(atts),
            "attachments": atts,
            "received_at": datetime.fromtimestamp(int(msg.get("internalDate", "0")) / 1000, tz=timezone.utc),
            "analysis_status": "pending",
        }
        await db.emails.insert_one(doc)
        processed += 1
        new_ids.append(gid)

    await db.users.update_one({"_id": user_id},
                              {"$set": {"gmail_last_cursor": "newer_than:1d",
                                        "gmail_last_synced_at": datetime.now(timezone.utc)}})
    return {"user_id": user_id, "processed": processed, "new_ids": new_ids}
