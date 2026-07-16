"""GmailSyncService — the orchestrator.

Owns the full sync workflow:

1. Choose sync mode (initial / incremental via ``history.list`` / resume).
2. Page through Gmail with backoff + rate-limit protection.
3. For each new/updated message: fetch metadata payload, transform via
   ``EmailMetadataService``, upsert through ``EmailRepository``,
   roll thread state via ``ThreadService``.
4. Persist run metrics via ``SyncLogsRepository`` and advance the
   connection cursor via ``GmailConnectionsRepository``.
5. Fan out per-message analysis tasks (``threat.analyze_gmail_message``)
   for downstream modules — this module never runs analysis itself.

Idempotent by design: gmail_id is the natural key; re-running a completed
sync produces zero new inserts and only status/label diffs.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from googleapiclient.errors import HttpError

from app.core.clock import now_utc
from app.core.logging import get_logger
from app.database.mongodb import get_db
from app.database.redis import get_redis
from app.models.gmail_connection import GmailConnection
from app.models.sync_log import SyncKind, SyncLog
from app.repositories.emails import EmailRepository
from app.repositories.gmail_connections import GmailConnectionsRepository
from app.repositories.sync_logs import SyncLogsRepository
from app.services.base import BaseService
from app.services.gmail.client import (GmailQuotaExceeded, GmailReauthRequired,
                                        build_service, get_message,
                                        list_history, list_messages)
from app.services.gmail.label_service import label_service
from app.services.gmail.metadata_service import email_metadata_service
from app.services.gmail.thread_service import thread_service

log = get_logger(__name__)

# Message metadata is enough for triage; we only pull full body on-demand.
METADATA_HEADERS = [
    "From", "To", "Cc", "Bcc", "Reply-To", "Return-Path",
    "Subject", "Date", "Message-ID",
    "Authentication-Results", "Received", "Received-SPF",
    "DKIM-Signature", "ARC-Authentication-Results",
    "X-Originating-IP", "X-Mailer", "User-Agent",
    "Content-Type", "List-Unsubscribe",
]

SYNC_LOCK_TTL_S = 60 * 30           # 30 min hard cap per user
INITIAL_IMPORT_QUERY = "newer_than:30d"
INCREMENTAL_PAGE_SIZE = 100
INITIAL_PAGE_SIZE = 100
FULL_BODY_ON_INGEST = False         # metadata-only by default (per spec)


@dataclass
class _Counters:
    scanned: int = 0
    ingested: int = 0
    updated: int = 0
    skipped: int = 0
    threads: int = 0
    api_calls: int = 0
    retries: int = 0
    new_gmail_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, int]:
        return {
            "messages_scanned": self.scanned,
            "messages_ingested": self.ingested,
            "messages_updated": self.updated,
            "messages_skipped": self.skipped,
            "threads_touched": self.threads,
            "api_calls": self.api_calls,
            "retries": self.retries,
        }


class GmailSyncService(BaseService):
    # ------------------------------------------------------------------ api
    async def sync_user(self, user_id: str, *, kind: SyncKind = "incremental") -> dict[str, Any]:
        db = get_db()
        conn = await GmailConnectionsRepository(db).get_active_for_user(user_id)
        if not conn:
            return {"user_id": user_id, "status": "skipped", "reason": "no_active_connection"}

        # single-flight per user
        lock_key = f"lock:gmail:sync:{user_id}"
        redis = get_redis()
        if not await redis.set(lock_key, "1", ex=SYNC_LOCK_TTL_S, nx=True):
            return {"user_id": user_id, "status": "skipped", "reason": "already_running"}

        try:
            return await self._run(conn, kind=kind)
        finally:
            try:
                await redis.delete(lock_key)
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ core
    async def _run(self, conn: GmailConnection, *, kind: SyncKind) -> dict[str, Any]:
        db = get_db()
        conns = GmailConnectionsRepository(db)
        logs_repo = SyncLogsRepository(db)

        # Decide effective mode
        effective: SyncKind
        if kind == "manual" or kind == "scheduled":
            effective = "incremental" if conn.history_id else "initial"
        elif kind == "incremental" and not conn.history_id:
            effective = "initial"
        else:
            effective = kind

        started_at = now_utc()
        run = SyncLog(
            user_id=conn.user_id,
            connection_id=conn.id,
            kind=effective,
            started_history_id=conn.history_id,
            started_at=started_at,
        )
        run_id = await logs_repo.start(run)
        counters = _Counters()

        await conns.update(
            {"_id": conn.id},
            {"$set": {"last_sync_started_at": started_at}},
        )

        try:
            service = build_service(conn.refresh_token_enc)
            counters.api_calls += 1

            if effective in ("initial", "resume") or not conn.history_id:
                new_history_id = await self._initial_import(service, conn, counters)
                initial_completed = True
            else:
                new_history_id = await self._incremental(service, conn, counters)
                initial_completed = None  # unchanged

            finished_at = now_utc()
            await conns.update_cursor(
                conn.id,
                history_id=new_history_id,
                ingested=counters.ingested,
                initial_completed=initial_completed if initial_completed else None,
                started_at=started_at,
                finished_at=finished_at,
            )
            await logs_repo.finish(
                run_id,
                status="success",
                counters=counters.as_dict(),
                ended_history_id=new_history_id,
            )
            self._fanout_analysis(conn.user_id, counters.new_gmail_ids)
            return {
                "user_id": conn.user_id,
                "connection_id": conn.id,
                "status": "success",
                "kind": effective,
                "history_id": new_history_id,
                "counters": counters.as_dict(),
            }

        except GmailReauthRequired as e:
            await conns.mark_error(conn.id, code="reauth", message=str(e))
            await logs_repo.finish(run_id, status="failed",
                                   counters=counters.as_dict(),
                                   error_code="reauth_required",
                                   error_message=str(e))
            log.warning("gmail_sync_reauth", user_id=conn.user_id)
            return {"user_id": conn.user_id, "status": "reauth_required"}

        except GmailQuotaExceeded as e:
            await conns.mark_error(conn.id, code="quota", message=str(e))
            await logs_repo.finish(run_id, status="partial",
                                   counters=counters.as_dict(),
                                   error_code="quota_exceeded",
                                   error_message=str(e))
            log.warning("gmail_sync_quota", user_id=conn.user_id)
            return {"user_id": conn.user_id, "status": "quota_exceeded"}

        except HttpError as e:
            await conns.mark_error(conn.id, code="http", message=str(e))
            await logs_repo.finish(run_id, status="failed",
                                   counters=counters.as_dict(),
                                   error_code=f"http_{getattr(e.resp, 'status', 'x')}",
                                   error_message=str(e))
            log.exception("gmail_sync_http_error", user_id=conn.user_id)
            raise

        except Exception as e:  # noqa: BLE001
            await conns.mark_error(conn.id, code="internal", message=str(e))
            await logs_repo.finish(run_id, status="failed",
                                   counters=counters.as_dict(),
                                   error_code="internal",
                                   error_message=str(e))
            log.exception("gmail_sync_failed", user_id=conn.user_id)
            raise

    # --------------------------------------------------------- initial full
    async def _initial_import(self, service, conn: GmailConnection, c: _Counters) -> str | None:
        emails = EmailRepository(get_db())
        page_token: str | None = None
        history_id: str | None = conn.history_id

        while True:
            resp = list_messages(
                service,
                query=INITIAL_IMPORT_QUERY,
                max_results=INITIAL_PAGE_SIZE,
                page_token=page_token,
            )
            c.api_calls += 1
            for meta in resp.get("messages", []):
                gid = meta["id"]
                c.scanned += 1
                existing = await emails.find_by_gmail_id(conn.user_id, gid)
                if existing:
                    c.skipped += 1
                    continue
                msg = get_message(service, gid, fmt="metadata",
                                  metadata_headers=METADATA_HEADERS)
                c.api_calls += 1
                await self._persist_message(conn, msg, counters=c, is_new=True)
                history_id = str(msg.get("historyId") or history_id)
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return history_id

    # --------------------------------------------------------- incremental
    async def _incremental(self, service, conn: GmailConnection, c: _Counters) -> str | None:
        assert conn.history_id
        emails = EmailRepository(get_db())
        page_token: str | None = None
        latest_history_id: str = conn.history_id

        while True:
            try:
                resp = list_history(
                    service,
                    start_history_id=conn.history_id,
                    page_token=page_token,
                )
            except HttpError as e:
                # 404 → history_id is too old; fall back to initial import
                if getattr(e.resp, "status", None) == 404:
                    log.info("gmail_history_gone", user_id=conn.user_id)
                    return await self._initial_import(service, conn, c)
                raise
            c.api_calls += 1

            latest_history_id = str(resp.get("historyId") or latest_history_id)

            for entry in resp.get("history", []) or []:
                for added in entry.get("messagesAdded", []) or []:
                    msg_stub = added.get("message") or {}
                    gid = msg_stub.get("id")
                    if not gid:
                        continue
                    c.scanned += 1
                    if await emails.find_by_gmail_id(conn.user_id, gid):
                        c.skipped += 1
                        continue
                    msg = get_message(service, gid, fmt="metadata",
                                      metadata_headers=METADATA_HEADERS)
                    c.api_calls += 1
                    await self._persist_message(conn, msg, counters=c, is_new=True)

                for removed in entry.get("messagesDeleted", []) or []:
                    gid = (removed.get("message") or {}).get("id")
                    if gid:
                        await emails.delete_by_gmail_id(conn.user_id, gid)

                for lbl in entry.get("labelsAdded", []) or []:
                    gid = (lbl.get("message") or {}).get("id")
                    ids = lbl.get("labelIds") or []
                    if gid and ids:
                        await emails.apply_labels(conn.user_id, gid, add=ids, remove=[])
                        c.updated += 1

                for lbl in entry.get("labelsRemoved", []) or []:
                    gid = (lbl.get("message") or {}).get("id")
                    ids = lbl.get("labelIds") or []
                    if gid and ids:
                        await emails.apply_labels(conn.user_id, gid, add=[], remove=ids)
                        c.updated += 1

            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return latest_history_id

    # ------------------------------------------------------------- persist
    async def _persist_message(
        self,
        conn: GmailConnection,
        msg: dict[str, Any],
        *,
        counters: _Counters,
        is_new: bool,
    ) -> None:
        doc = email_metadata_service.build(
            user_id=conn.user_id,
            connection_id=conn.id,
            msg=msg,
            keep_body=FULL_BODY_ON_INGEST,
        )
        emails = EmailRepository(get_db())
        _, inserted = await emails.upsert_by_gmail_id(doc)
        if inserted:
            counters.ingested += 1
            if doc.gmail_id:
                counters.new_gmail_ids.append(doc.gmail_id)
        else:
            counters.updated += 1
        try:
            await thread_service.upsert_from_email(doc)
            counters.threads += 1
        except Exception:  # noqa: BLE001
            self.log.warning("thread_upsert_failed", gmail_id=doc.gmail_id)

    # ---------------------------------------------------------- fan-out
    def _fanout_analysis(self, user_id: str, gmail_ids: list[str]) -> None:
        """Enqueue downstream analysis; import late to avoid celery cycles."""
        if not gmail_ids:
            return
        try:
            from app.workers.celery_app import celery
            for gid in gmail_ids:
                celery.send_task(
                    "threat.analyze_gmail_message",
                    args=[user_id, gid],
                    queue="threat",
                )
        except Exception:  # noqa: BLE001
            self.log.warning("analysis_fanout_failed", count=len(gmail_ids))


gmail_sync_service = GmailSyncService()


# ---- legacy shim: preserved so older callers keep working ----------------
async def sync_user(user_id: str) -> dict[str, Any]:  # pragma: no cover - shim
    return await gmail_sync_service.sync_user(user_id, kind="scheduled")
