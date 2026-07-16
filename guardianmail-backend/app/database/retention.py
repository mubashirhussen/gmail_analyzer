"""Data retention configuration + cleanup runner.

Retention policies live in one place so ops can audit them. Two
mechanisms are used depending on collection semantics:

* **TTL indexes** — Mongo evicts documents automatically. Used for
  transient, append-only rows (sessions, refresh tokens, notifications,
  login history). Configured in `app/database/indexes.py`.
* **Scheduled soft-delete + purge** — for tombstoned rows on domain
  tables (threats, emails, complaints, evidence). A Celery beat task
  calls `run_retention()` daily.

Retention windows come from settings so they can differ per environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.clock import now_utc
from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class RetentionPolicy:
    collection: str
    field: str = "created_at"
    #: hard-delete rows soft-deleted longer than this
    purge_after_days: int | None = 30
    #: hard-delete live rows older than this (None = never)
    max_age_days: int | None = None


DEFAULT_POLICIES: list[RetentionPolicy] = [
    # append-only telemetry — hard-cap age
    RetentionPolicy("audit_logs", field="at", purge_after_days=None, max_age_days=365),
    RetentionPolicy("login_history", field="at", purge_after_days=None, max_age_days=180),
    RetentionPolicy("security_events", field="created_at", purge_after_days=None, max_age_days=365),
    RetentionPolicy("background_jobs", field="finished_at", purge_after_days=None, max_age_days=30),
    RetentionPolicy("analytics", field="at", purge_after_days=None, max_age_days=730),
    # domain tables — purge tombstones after grace period
    RetentionPolicy("emails", purge_after_days=30, max_age_days=None),
    RetentionPolicy("threats", purge_after_days=30, max_age_days=None),
    RetentionPolicy("threat_indicators", purge_after_days=30, max_age_days=None),
    RetentionPolicy("complaints", purge_after_days=90, max_age_days=None),
    RetentionPolicy("evidence_packs", purge_after_days=90, max_age_days=None),
]


async def _purge_soft_deleted(db: AsyncIOMotorDatabase, p: RetentionPolicy) -> dict[str, Any]:
    cutoff = now_utc() - timedelta(days=p.purge_after_days or 0)
    res = await db[p.collection].delete_many(
        {"deleted_at": {"$ne": None, "$lte": cutoff}}
    )
    return {"purged": res.deleted_count}


async def _cap_age(db: AsyncIOMotorDatabase, p: RetentionPolicy) -> dict[str, Any]:
    cutoff = now_utc() - timedelta(days=p.max_age_days or 0)
    res = await db[p.collection].delete_many({p.field: {"$lt": cutoff}})
    return {"aged_out": res.deleted_count}


async def run_retention(
    db: AsyncIOMotorDatabase, policies: list[RetentionPolicy] | None = None
) -> dict[str, dict[str, Any]]:
    """Apply every retention policy. Safe to call daily via Celery beat."""
    results: dict[str, dict[str, Any]] = {}
    for policy in policies or DEFAULT_POLICIES:
        try:
            summary: dict[str, Any] = {}
            if policy.purge_after_days is not None:
                summary.update(await _purge_soft_deleted(db, policy))
            if policy.max_age_days is not None:
                summary.update(await _cap_age(db, policy))
            results[policy.collection] = summary
            log.info("retention_applied", collection=policy.collection, **summary)
        except Exception as e:  # pragma: no cover - infra
            log.exception("retention_failed", collection=policy.collection, err=str(e))
            results[policy.collection] = {"error": str(e)}
    return results
