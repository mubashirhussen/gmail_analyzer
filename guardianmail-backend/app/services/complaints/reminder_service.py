"""Reminder scheduling for complaint drafts (Module 9).

Persists reminders in `complaint_reminders` and lets a Celery sweeper
promote due entries to notifications via the existing notification
service (module 8). We never auto-submit a complaint on the user's
behalf — reminders only nudge the user to review + export.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from bson import ObjectId

from app.database.mongodb import get_db


ReminderStatus = Literal["scheduled", "sent", "cancelled"]
ReminderPreset = Literal["tomorrow", "next_week", "custom"]


def _preset_to_datetime(preset: ReminderPreset, when: datetime | None) -> datetime:
    now = datetime.now(timezone.utc)
    if preset == "tomorrow":
        return now + timedelta(days=1)
    if preset == "next_week":
        return now + timedelta(days=7)
    if preset == "custom":
        if not when:
            raise ValueError("custom reminder requires 'when'")
        if when <= now:
            raise ValueError("reminder must be in the future")
        return when.astimezone(timezone.utc)
    raise ValueError(f"unknown preset {preset}")


async def schedule(
    *, user_id: str, complaint_id: str,
    preset: ReminderPreset, when: datetime | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    db = get_db()
    complaint = await db.complaints.find_one(
        {"_id": ObjectId(complaint_id), "user_id": user_id}
    )
    if not complaint:
        raise ValueError("complaint not found")
    fire_at = _preset_to_datetime(preset, when)
    doc = {
        "user_id": user_id,
        "complaint_id": ObjectId(complaint_id),
        "preset": preset,
        "fire_at": fire_at,
        "status": "scheduled",
        "note": note,
        "created_at": datetime.now(timezone.utc),
        "sent_at": None,
    }
    result = await db.complaint_reminders.insert_one(doc)
    return _serialize({**doc, "_id": result.inserted_id})


async def cancel(user_id: str, reminder_id: str) -> None:
    db = get_db()
    updated = await db.complaint_reminders.update_one(
        {"_id": ObjectId(reminder_id), "user_id": user_id, "status": "scheduled"},
        {"$set": {"status": "cancelled"}},
    )
    if not updated.matched_count:
        raise ValueError("reminder not found or already fired")


async def list_for_user(user_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    db = get_db()
    cur = db.complaint_reminders.find(
        {"user_id": user_id}, sort=[("fire_at", 1)], limit=limit,
    )
    return [_serialize(d) async for d in cur]


async def sweep_due(now: datetime | None = None) -> list[dict[str, Any]]:
    """Return reminders eligible to fire (fire_at ≤ now)."""
    db = get_db()
    now = now or datetime.now(timezone.utc)
    cur = db.complaint_reminders.find({
        "status": "scheduled",
        "fire_at": {"$lte": now},
    })
    return [_serialize(d) async for d in cur]


async def mark_sent(reminder_id: str) -> None:
    db = get_db()
    await db.complaint_reminders.update_one(
        {"_id": ObjectId(reminder_id)},
        {"$set": {"status": "sent", "sent_at": datetime.now(timezone.utc)}},
    )


def _serialize(d: dict[str, Any]) -> dict[str, Any]:
    return {
        **d,
        "_id": str(d["_id"]),
        "complaint_id": str(d["complaint_id"]) if d.get("complaint_id") else None,
    }
