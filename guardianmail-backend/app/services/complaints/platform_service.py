"""Complaint & Evidence Platform orchestrator (Module 9).

Combines existing scan artefacts (threat report, AI report, indicators,
URLs, headers, OCR/QR/attachment metadata) into a signed evidence bundle
plus a structured complaint draft ready for user review.

The service intentionally **never** submits complaints to external
authorities. Its outputs are always downloadable artefacts that the user
manually files.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId

from app.database.mongodb import get_db
from app.services.complaints.download_logs import record as record_download
from app.services.complaints.template_registry import (
    COMPLAINT_DESTINATIONS, category_label, get_template,
)
from app.services.evidence import exporters
from app.services.evidence.integrity import (
    canonical_json, custody_trail, hmac_signature, integrity_envelope,
    record_custody_event, sha256_hex, verify_envelope,
)
from app.services.evidence.validator import (
    ValidationResult, validate_for_evidence,
)


VALID_STATUSES = {"draft", "reviewed", "ready", "exported", "archived", "cancelled"}
STATUS_TRANSITIONS = {
    "draft": {"reviewed", "cancelled", "archived"},
    "reviewed": {"ready", "cancelled", "archived"},
    "ready": {"exported", "archived", "cancelled"},
    "exported": {"archived"},
    "archived": set(),
    "cancelled": set(),
}


# --------------------------------------------------------------------------- #
# Evidence pack                                                               #
# --------------------------------------------------------------------------- #
async def generate_evidence_pack(
    *, user_id: str, threat_id: str, include_body: bool = False,
) -> dict[str, Any]:
    """Validate + assemble + persist a signed evidence pack."""
    validation = await validate_for_evidence(user_id, threat_id)
    if not validation.ok:
        raise ValueError(
            f"evidence validation failed: missing={validation.missing}"
        )

    bundle = await _assemble_bundle(user_id, validation, include_body=include_body)
    pack_id = ObjectId()
    envelope = integrity_envelope(str(pack_id), bundle["manifest"])
    bundle["integrity"] = envelope
    bundle["integrity"]["pack_id"] = str(pack_id)

    doc = {
        "_id": pack_id,
        "user_id": user_id,
        "threat_report_id": threat_id,
        "manifest": bundle["manifest"],
        "sha256": envelope["sha256"],
        "signature": envelope["signature"],
        "version": envelope["version"],
        "download_count": 0,
        "last_accessed_at": None,
        "created_at": datetime.now(timezone.utc),
        "validation": validation.to_dict(),
    }
    db = get_db()
    await db.evidence_packs.insert_one(doc)
    await record_custody_event(
        str(pack_id),
        user_id=user_id,
        event="pack_generated",
        detail={"threat_id": threat_id, "sha256": envelope["sha256"]},
    )
    bundle["_pack_doc"] = _serialize(doc)
    return bundle


async def _assemble_bundle(
    user_id: str, validation: ValidationResult, *, include_body: bool,
) -> dict[str, Any]:
    db = get_db()
    threat = validation.threat or {}
    threat_id = str(threat["_id"])
    ai = validation.ai_report or {}

    urls_cur = db.threat_urls.find({"threat_id": threat_id, "user_id": user_id})
    urls = [
        {"url": u.get("url"), "flagged": bool(u.get("flagged")),
         "flagged_by": u.get("flagged_by") or []}
        async for u in urls_cur
    ]
    if not urls:
        urls = threat.get("urls") or []

    headers = threat.get("headers") or {}
    auth = {
        "spf": threat.get("spf") or headers.get("spf"),
        "dkim": threat.get("dkim") or headers.get("dkim"),
        "dmarc": threat.get("dmarc") or headers.get("dmarc"),
        "received": headers.get("received"),
    }

    attachments = threat.get("attachments") or []
    attachments = [
        {"name": a.get("name"), "mime": a.get("mime"),
         "size": a.get("size"), "sha256": a.get("sha256")}
        for a in attachments
    ]

    ocr = await db.ocr_reports.find_one(
        {"threat_id": threat_id, "user_id": user_id},
        sort=[("created_at", -1)],
    )
    qr = threat.get("qr_analysis") or (ocr or {}).get("qr_analysis")

    provider_results_cur = db.provider_results.find(
        {"threat_id": threat_id}, limit=200,
    )
    provider_results = [
        {"provider": p.get("provider"), "verdict": p.get("verdict"),
         "score": p.get("score"), "detail": p.get("detail")}
        async for p in provider_results_cur
    ]

    timeline_cur = db.threat_timeline.find(
        {"threat_id": threat_id, "user_id": user_id},
        sort=[("at", 1)], limit=200,
    )
    timeline = [
        {"at": t.get("at"), "event": t.get("event"), "detail": t.get("detail")}
        async for t in timeline_cur
    ]

    summary = {
        "verdict": threat.get("verdict"),
        "risk_score": threat.get("risk_score"),
        "confidence": threat.get("confidence"),
        "attack_category": threat.get("attack_category"),
        "sender": threat.get("sender"),
        "received_at": threat.get("created_at"),
    }
    message = {
        "sender": threat.get("sender"),
        "recipient": threat.get("recipient"),
        "subject": threat.get("subject"),
        "message_id": threat.get("message_id"),
        "thread_id": threat.get("thread_id"),
        "received_at": threat.get("created_at"),
    }
    if include_body:
        message["body_snippet"] = (threat.get("body") or "")[:5000]

    trail = await custody_trail(str(threat.get("_id"))) if threat.get("_id") else []

    manifest = {
        "summary": summary,
        "message": message,
        "authentication": auth,
        "indicators": [
            {"severity": i.get("severity"), "category": i.get("category"),
             "detail": i.get("detail")}
            for i in validation.indicators
        ],
        "urls": urls,
        "attachments": attachments,
        "ocr": {
            "text_length": len((ocr or {}).get("text") or ""),
            "sensitive_hits": (ocr or {}).get("sensitive_hits") or [],
        } if ocr else None,
        "qr_analysis": qr,
        "provider_results": provider_results,
        "timeline": timeline,
        "ai_report": {
            "verdict": ai.get("verdict"),
            "summary": ai.get("summary"),
            "confidence": ai.get("confidence"),
            "recommendations": ai.get("recommendations") or [],
        } if ai else None,
    }

    return {
        "manifest": manifest,
        "summary": summary,
        "message": message,
        "authentication": auth,
        "indicators": manifest["indicators"],
        "urls": urls,
        "attachments": attachments,
        "timeline": timeline,
        "ai_report": manifest["ai_report"],
        "chain_of_custody": trail,
    }


async def get_pack(user_id: str, pack_id: str) -> dict[str, Any]:
    db = get_db()
    doc = await db.evidence_packs.find_one(
        {"_id": ObjectId(pack_id), "user_id": user_id}
    )
    if not doc:
        raise ValueError("evidence pack not found")
    return _serialize(doc)


async def load_bundle_for_export(user_id: str, pack_id: str) -> dict[str, Any]:
    db = get_db()
    doc = await db.evidence_packs.find_one(
        {"_id": ObjectId(pack_id), "user_id": user_id}
    )
    if not doc:
        raise ValueError("evidence pack not found")
    manifest = doc["manifest"]
    trail = await custody_trail(str(doc["_id"]))
    envelope = {
        "pack_id": str(doc["_id"]),
        "version": doc.get("version", 1),
        "created_at": doc["created_at"].isoformat(),
        "sha256": doc["sha256"],
        "signature": doc["signature"],
        "manifest": manifest,
    }
    return {
        "manifest": manifest,
        "summary": manifest.get("summary", {}),
        "message": manifest.get("message", {}),
        "authentication": manifest.get("authentication", {}),
        "indicators": manifest.get("indicators", []),
        "urls": manifest.get("urls", []),
        "attachments": manifest.get("attachments", []),
        "timeline": manifest.get("timeline", []),
        "ai_report": manifest.get("ai_report"),
        "chain_of_custody": trail,
        "integrity": envelope,
    }


async def verify_pack(user_id: str, pack_id: str) -> dict[str, Any]:
    bundle = await load_bundle_for_export(user_id, pack_id)
    ok, reason = verify_envelope(bundle["integrity"])
    return {
        "pack_id": pack_id, "ok": ok, "reason": reason,
        "sha256": bundle["integrity"]["sha256"],
    }


async def export_pack(
    *, user_id: str, pack_id: str, fmt: str,
    ip: str | None = None, user_agent: str | None = None,
) -> tuple[bytes, str, str]:
    bundle = await load_bundle_for_export(user_id, pack_id)
    data, mime = exporters.render(bundle, fmt)
    await record_download(
        pack_id=pack_id, user_id=user_id, fmt=fmt,
        ip=ip, user_agent=user_agent, size=len(data),
    )
    await record_custody_event(
        pack_id, user_id=user_id, event="exported",
        detail={"format": fmt, "bytes": len(data)},
    )
    filename = f"guardianmail-evidence-{pack_id}.{fmt}"
    return data, mime, filename


# --------------------------------------------------------------------------- #
# Signed download URLs                                                        #
# --------------------------------------------------------------------------- #
def issue_download_token(pack_id: str, fmt: str, user_id: str,
                         ttl_seconds: int = 300) -> dict[str, Any]:
    from app.core.jwt import jwt as _jwt  # optional
    exp = int(datetime.now(timezone.utc).timestamp()) + ttl_seconds
    nonce = secrets.token_urlsafe(12)
    payload = f"{pack_id}|{fmt}|{user_id}|{exp}|{nonce}"
    sig = hmac_signature(payload.encode())
    return {
        "pack_id": pack_id, "format": fmt, "expires_at": exp,
        "nonce": nonce, "signature": sig,
    }


def verify_download_token(pack_id: str, fmt: str, user_id: str,
                          exp: int, nonce: str, signature: str) -> bool:
    now = int(datetime.now(timezone.utc).timestamp())
    if now > exp:
        return False
    payload = f"{pack_id}|{fmt}|{user_id}|{exp}|{nonce}"
    return hmac_signature(payload.encode()) == signature


# --------------------------------------------------------------------------- #
# Complaint drafts                                                            #
# --------------------------------------------------------------------------- #
async def generate_complaint(
    *, user_id: str, threat_id: str, destination: str,
    category: str, locale: str = "en",
    victim: dict[str, str] | None = None,
    recommended_action: str | None = None,
    include_body: bool = False,
    evidence_pack_id: str | None = None,
) -> dict[str, Any]:
    if destination not in COMPLAINT_DESTINATIONS:
        raise ValueError(f"unknown destination {destination}")
    db = get_db()

    if evidence_pack_id:
        bundle = await load_bundle_for_export(user_id, evidence_pack_id)
        pack_id = evidence_pack_id
    else:
        bundle = await generate_evidence_pack(
            user_id=user_id, threat_id=threat_id, include_body=include_body,
        )
        pack_id = bundle["integrity"]["pack_id"]

    manifest = bundle["manifest"]
    summary = manifest.get("summary", {})
    message = manifest.get("message", {})
    auth = manifest.get("authentication", {})
    urls = [u.get("url") for u in manifest.get("urls", []) if u.get("url")]
    indicators = [
        f"[{i.get('severity','?')}] {i.get('category')} — {i.get('detail')}"
        for i in manifest.get("indicators", [])
    ]

    user = await db.users.find_one({"_id": ObjectId(user_id)}) or {}
    ctx = {
        "victim_name": (victim or {}).get("name") or user.get("name"),
        "victim_email": (victim or {}).get("email") or user.get("email"),
        "victim_phone": (victim or {}).get("phone"),
        "category_label": category_label(category),
        "sender": summary.get("sender") or message.get("sender"),
        "subject_line": message.get("subject"),
        "message_id": message.get("message_id"),
        "received_at": (message.get("received_at") or summary.get("received_at")
                        or datetime.now(timezone.utc).isoformat()),
        "verdict": summary.get("verdict"),
        "risk_score": summary.get("risk_score"),
        "confidence": summary.get("confidence"),
        "attack_category": summary.get("attack_category"),
        "spf": auth.get("spf"),
        "dkim": auth.get("dkim"),
        "dmarc": auth.get("dmarc"),
        "indicators": indicators,
        "urls": urls,
        "ai_summary": (manifest.get("ai_report") or {}).get("summary") if manifest.get("ai_report") else None,
        "recommended_action": recommended_action,
        "evidence_id": pack_id,
        "evidence_hash": bundle["integrity"]["sha256"],
        "evidence_generated_at": bundle["integrity"]["created_at"],
        "chain_of_custody_id": pack_id,
    }
    template = await get_template(destination, category, locale=locale)
    rendered = template.render(ctx)

    now = datetime.now(timezone.utc)
    complaint_doc = {
        "user_id": user_id,
        "threat_id": ObjectId(threat_id),
        "evidence_pack_id": ObjectId(pack_id),
        "evidence_hash": bundle["integrity"]["sha256"],
        "destination": destination,
        "category": category,
        "locale": locale,
        "template_version": template.version,
        "subject": rendered["subject"],
        "body": rendered["body"],
        "draft_hash": sha256_hex(canonical_json({
            "subject": rendered["subject"], "body": rendered["body"],
        })),
        "urls": urls,
        "indicator_count": len(indicators),
        "status": "draft",
        "reminder_id": None,
        "download_count": 0,
        "last_accessed_at": None,
        "history": [{"at": now, "event": "created", "status": "draft"}],
        "created_at": now,
        "updated_at": now,
        "victim": victim,
    }
    result = await db.complaints.insert_one(complaint_doc)
    complaint_doc["_id"] = result.inserted_id
    await record_custody_event(
        pack_id, user_id=user_id, event="complaint_drafted",
        detail={"complaint_id": str(result.inserted_id),
                "destination": destination, "category": category},
    )
    return _serialize_complaint(complaint_doc)


async def get_complaint(user_id: str, complaint_id: str) -> dict[str, Any]:
    db = get_db()
    doc = await db.complaints.find_one(
        {"_id": ObjectId(complaint_id), "user_id": user_id}
    )
    if not doc:
        raise ValueError("complaint not found")
    return _serialize_complaint(doc)


async def update_complaint(
    user_id: str, complaint_id: str,
    *, subject: str | None = None, body: str | None = None,
) -> dict[str, Any]:
    db = get_db()
    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if subject is not None:
        updates["subject"] = subject
    if body is not None:
        updates["body"] = body
    if subject is not None or body is not None:
        current = await db.complaints.find_one(
            {"_id": ObjectId(complaint_id), "user_id": user_id}
        )
        if not current:
            raise ValueError("complaint not found")
        new_subject = subject if subject is not None else current["subject"]
        new_body = body if body is not None else current["body"]
        updates["draft_hash"] = sha256_hex(canonical_json({
            "subject": new_subject, "body": new_body,
        }))
    result = await db.complaints.find_one_and_update(
        {"_id": ObjectId(complaint_id), "user_id": user_id},
        {"$set": updates,
         "$push": {"history": {
             "at": datetime.now(timezone.utc), "event": "edited",
         }}},
        return_document=True,
    )
    if not result:
        raise ValueError("complaint not found")
    return _serialize_complaint(result)


async def transition_complaint(
    user_id: str, complaint_id: str, status: str, note: str | None = None,
) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status {status}")
    db = get_db()
    current = await db.complaints.find_one(
        {"_id": ObjectId(complaint_id), "user_id": user_id}
    )
    if not current:
        raise ValueError("complaint not found")
    from_status = current.get("status", "draft")
    if status not in STATUS_TRANSITIONS.get(from_status, set()) and status != from_status:
        raise ValueError(f"cannot transition {from_status} → {status}")
    entry: dict[str, Any] = {
        "at": datetime.now(timezone.utc), "event": "transition",
        "from": from_status, "to": status,
    }
    if note:
        entry["note"] = note
    updated = await db.complaints.find_one_and_update(
        {"_id": ObjectId(complaint_id), "user_id": user_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)},
         "$push": {"history": entry}},
        return_document=True,
    )
    return _serialize_complaint(updated)


async def delete_complaint(user_id: str, complaint_id: str) -> None:
    db = get_db()
    result = await db.complaints.update_one(
        {"_id": ObjectId(complaint_id), "user_id": user_id},
        {"$set": {"status": "cancelled",
                  "updated_at": datetime.now(timezone.utc)},
         "$push": {"history": {
             "at": datetime.now(timezone.utc), "event": "deleted",
         }}},
    )
    if not result.matched_count:
        raise ValueError("complaint not found")


async def list_complaints(
    user_id: str, *, status: str | None = None,
    destination: str | None = None, category: str | None = None,
    limit: int = 50, skip: int = 0,
) -> list[dict[str, Any]]:
    db = get_db()
    q: dict[str, Any] = {"user_id": user_id}
    if status:
        q["status"] = status
    if destination:
        q["destination"] = destination
    if category:
        q["category"] = category
    cur = db.complaints.find(q, sort=[("created_at", -1)], skip=skip, limit=limit)
    return [_serialize_complaint(d) async for d in cur]


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _serialize(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        **doc,
        "_id": str(doc["_id"]),
    }


def _serialize_complaint(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        **doc,
        "_id": str(doc["_id"]),
        "threat_id": str(doc["threat_id"]) if doc.get("threat_id") else None,
        "evidence_pack_id": str(doc["evidence_pack_id"]) if doc.get("evidence_pack_id") else None,
    }
