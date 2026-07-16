"""SyncMonitoringService — user-facing sync health projection.

Aggregates connection state and last-N sync logs into a compact status
payload the UI polls.
"""
from __future__ import annotations

from typing import Any

from app.database.mongodb import get_db
from app.repositories.gmail_connections import GmailConnectionsRepository
from app.repositories.sync_logs import SyncLogsRepository


class SyncMonitoringService:
    async def status(self, user_id: str) -> dict[str, Any]:
        db = get_db()
        conn = await GmailConnectionsRepository(db).get_active_for_user(user_id)
        if not conn:
            return {"connected": False}
        logs = SyncLogsRepository(db)
        last_success = await logs.last_success(user_id)
        recent = await logs.history(user_id, page=1, page_size=5)
        return {
            "connected": True,
            "email": conn.email,
            "status": conn.status,
            "history_id": conn.history_id,
            "initial_import_completed": conn.initial_import_completed,
            "messages_synced_total": conn.messages_synced_total,
            "last_success_at": last_success.finished_at if last_success else None,
            "last_sync_started_at": conn.last_sync_started_at,
            "last_sync_finished_at": conn.last_sync_finished_at,
            "last_error": conn.last_error,
            "last_error_at": conn.last_error_at,
            "recent_runs": [
                {
                    "id": r.id,
                    "kind": r.kind,
                    "status": r.status,
                    "started_at": r.started_at,
                    "finished_at": r.finished_at,
                    "duration_ms": r.duration_ms,
                    "messages_ingested": r.messages_ingested,
                    "messages_updated": r.messages_updated,
                    "api_calls": r.api_calls,
                    "error_code": r.error_code,
                }
                for r in recent.items
            ],
        }


sync_monitoring_service = SyncMonitoringService()
