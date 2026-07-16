"""Complaint lifecycle: draft → schedule → download / submit → history."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId

from app.database.mongodb import get_db
from app.services.complaints.templates import render
from app.services.evidence.pack import build as build_pack


VALID_STATUSES = {"drafted", "scheduled", "downloaded", "submitted", "cancelled"}
VALID_DESTINATIONS = {"cybercrime_gov_in", "report_phishing"}


def _category_from_verdict(verdict: str) -> str:
    v = (verdict or "").lower()
    if v == "fraud":
        return "fraud"
    if v in ("phishing", "malware"):
        return "phishing"
    return "suspicious"


async def draft_from_threat(
    user_id: str,
    threat_id: str,
    destination: str,
    scheduled_for: datetime | None = None,
    victim: dict[str, str] | None = None,
    include_body: bool = False,
) -> dict[str, Any]:
    if destination not in VALID_DESTINATIONS:
        raise ValueError(f"unknown destination {destination}")
    db = get_db()
    threat = await db.threats.find_one({"_id": ObjectId(threat_id), "user_id": user_id})
    if not threat:
        raise ValueError("threat not found")

    pack = await build_pack(user_id, threat_id, include_body=include_body)

    urls = [u["url"] for u in pack["urls"] if u.get("url")]
    indicators = [f"{i.get('category')} — {i.get('detail')}" for i in pack["indicators"]]
    category = _category_from_verdict(threat.get("verdict", ""))

    user = await db.users.find_one({"_id": ObjectId(user_id)}) or {}
    ctx = {
        "victim_name": (victim or {}).get("name") or user.get("name"),
        "victim_email": (victim or {}).get("email") or user.get("email"),
        "victim_phone": (victim or {}).get("phone"),
        "sender": threat.get("sender"),
        "subject": threat.get("subject"),
        "message_id": threat.get("message_id"),
        "received_at": (threat.get("created_at") or datetime.now(timezone.utc)).isoformat(),
        "verdict": threat.get("verdict"),
        "risk_score": threat.get("risk_score"),
        "confidence": threat.get("confidence"),
        "attack_category": threat.get("attack_category"),
        "indicators": indicators,
        "urls": urls,
        "evidence_id": pack["pack_id"],
        "evidence_hash": pack["sha256"],
    }
    rendered = await render(destination, category, ctx)

    now = datetime.now(timezone.utc)
    status = "scheduled" if scheduled_for and scheduled_for > now else "drafted"
    doc = {
        "user_id": user_id,
        "threat_id": ObjectId(threat_id),
        "evidence_pack_id": ObjectId(pack["pack_id"]),
        "evidence_hash": pack["sha256"],
        "destination": destination,
        "category": category,
        "subject": rendered["subject"],
        "body": rendered["body"],
        "urls": urls,
        "indicator_count": len(indicators),
        "status": status,
        "scheduled_for": scheduled_for,
        "reminder_sent": False,
        "history": [{"at": now, "event": "created", "status": status}],
        "created_at": now,
        "updated_at": now,
    }
    result = await db.complaints.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    doc["threat_id"] = str(doc["threat_id"])
    doc["evidence_pack_id"] = str(doc["evidence_pack_id"])
    return doc


async def transition(user_id: str, complaint_id: str, status: str, note: str | None = None) -> dict:
    if status not in VALID_STATUSES:
        raise ValueError("invalid status")
    db = get_db()
    now = datetime.now(timezone.utc)
    entry = {"at": now, "event": "transition", "status": status}
    if note:
        entry["note"] = note
    updated = await db.complaints.find_one_and_update(
        {"_id": ObjectId(complaint_id), "user_id": user_id},
        {"$set": {"status": status, "updated_at": now},
         "$push": {"history": entry}},
        return_document=True,
    )
    if not updated:
        raise ValueError("complaint not found")
    return _serialize(updated)


async def list_history(
    user_id: str,
    status: str | None = None,
    destination: str | None = None,
    category: str | None = None,
    limit: int = 50,
) -> list[dict]:
    db = get_db()
    q: dict[str, Any] = {"user_id": user_id}
    if status:
        q["status"] = status
    if destination:
        q["destination"] = destination
    if category:
        q["category"] = category
    cur = db.complaints.find(q, sort=[("created_at", -1)], limit=limit)
    return [_serialize(d) async for d in cur]


async def get_one(user_id: str, complaint_id: str) -> dict:
    db = get_db()
    doc = await db.complaints.find_one({"_id": ObjectId(complaint_id), "user_id": user_id})
    if not doc:
        raise ValueError("complaint not found")
    return _serialize(doc)


def _serialize(d: dict) -> dict:
    return {
        **d,
        "_id": str(d["_id"]),
        "threat_id": str(d["threat_id"]) if d.get("threat_id") else None,
        "evidence_pack_id": str(d["evidence_pack_id"]) if d.get("evidence_pack_id") else None,
    }


async def due_reminders(now: datetime | None = None) -> list[dict]:
    """Scheduled complaints whose window is within the next 15 minutes."""
    from datetime import timedelta
    db = get_db()
    now = now or datetime.now(timezone.utc)
    horizon = now + timedelta(minutes=15)
    cur = db.complaints.find({
        "status": "scheduled", "reminder_sent": False,
        "scheduled_for": {"$lte": horizon},
    })
    return [_serialize(d) async for d in cur]


async def mark_reminded(complaint_id: str) -> None:
    db = get_db()
    await db.complaints.update_one(
        {"_id": ObjectId(complaint_id)},
        {"$set": {"reminder_sent": True},
         "$push": {"history": {"at": datetime.now(timezone.utc), "event": "reminder"}}},
    )
