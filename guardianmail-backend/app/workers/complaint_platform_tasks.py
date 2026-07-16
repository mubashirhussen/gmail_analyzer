"""Celery tasks for Module 9 — Complaint Management & Digital Evidence.

Adds an async workflow so heavy exports can be dispatched by the task
platform (module 8):

  complaints_platform.generate_evidence_pack
  complaints_platform.generate_complaint_draft
  complaints_platform.sweep_reminders
  complaints_platform.export_pack
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.database.mongodb import mongodb
from app.services.complaints import platform_service, reminder_service
from app.services.notifications.sender import send as send_notification
from app.workers.celery_app import celery


async def _bootstrap():
    if mongodb.db is None:
        await mongodb.connect()


@celery.task(name="complaints_platform.generate_evidence_pack",
             bind=True, max_retries=3, default_retry_delay=15)
def generate_evidence_pack(self, user_id: str, threat_id: str,
                           include_body: bool = False) -> dict[str, Any]:
    async def run():
        await _bootstrap()
        bundle = await platform_service.generate_evidence_pack(
            user_id=user_id, threat_id=threat_id, include_body=include_body,
        )
        envelope = bundle["integrity"]
        return {"pack_id": envelope["pack_id"], "sha256": envelope["sha256"]}
    try:
        return asyncio.run(run())
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover
        raise self.retry(exc=exc)


@celery.task(name="complaints_platform.generate_complaint_draft",
             bind=True, max_retries=3, default_retry_delay=15)
def generate_complaint_draft(self, user_id: str, threat_id: str,
                             destination: str, category: str,
                             locale: str = "en",
                             include_body: bool = False,
                             victim: dict | None = None) -> dict[str, Any]:
    async def run():
        await _bootstrap()
        return await platform_service.generate_complaint(
            user_id=user_id, threat_id=threat_id,
            destination=destination, category=category,
            locale=locale, include_body=include_body, victim=victim,
        )
    try:
        return asyncio.run(run())
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover
        raise self.retry(exc=exc)


@celery.task(name="complaints_platform.export_pack",
             bind=True, max_retries=2, default_retry_delay=10)
def export_pack(self, user_id: str, pack_id: str, fmt: str) -> dict[str, Any]:
    async def run():
        await _bootstrap()
        data, mime, filename = await platform_service.export_pack(
            user_id=user_id, pack_id=pack_id, fmt=fmt,
        )
        return {"pack_id": pack_id, "format": fmt, "size": len(data), "mime": mime,
                "filename": filename}
    try:
        return asyncio.run(run())
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover
        raise self.retry(exc=exc)


@celery.task(name="complaints_platform.sweep_reminders")
def sweep_reminders() -> dict[str, Any]:
    async def run():
        await _bootstrap()
        sent = 0
        for r in await reminder_service.sweep_due():
            try:
                await send_notification(
                    user_id=r["user_id"],
                    kind="complaint_reminder",
                    title="Complaint ready to review",
                    body=(r.get("note") or
                          "Your scheduled complaint draft is ready for review."),
                    meta={"complaint_id": r["complaint_id"],
                          "reminder_id": r["_id"]},
                )
                await reminder_service.mark_sent(r["_id"])
                sent += 1
            except Exception:  # pragma: no cover - notification failure
                continue
        return {"reminders_sent": sent}
    return asyncio.run(run())
