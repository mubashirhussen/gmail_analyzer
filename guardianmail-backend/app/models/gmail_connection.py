"""Gmail connection document.

One row per (user, google_account) linkage. Refresh token stored AES-GCM
encrypted; access tokens are never persisted (rebuilt on demand).

Kept as a dedicated collection rather than folded into ``User`` so we can:

* revoke / rotate / disconnect independently of the identity record,
* store per-connection sync cursors (``history_id``, ``last_full_sync_at``),
* support future multi-account linking (personal + work Gmail),
* apply targeted TTLs / retention without touching the identity row.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import EmailStr, Field

from app.models.base import Document

ConnectionStatus = Literal[
    "active",         # healthy, tokens refreshable
    "reauth_required",# refresh token rejected → user must reconnect
    "revoked",        # user disconnected
    "quota_paused",   # temporarily paused due to Gmail 429/quota
    "error",          # unrecoverable error, needs manual attention
]


class GmailConnection(Document):
    user_id: str
    email: EmailStr
    google_sub: str | None = None

    # OAuth material
    refresh_token_enc: str
    scopes: list[str] = Field(default_factory=list)

    status: ConnectionStatus = "active"
    last_error: str | None = None
    last_error_at: datetime | None = None

    # sync cursors
    history_id: str | None = None          # Gmail history cursor
    initial_import_completed: bool = False
    last_sync_started_at: datetime | None = None
    last_sync_finished_at: datetime | None = None
    last_success_at: datetime | None = None
    messages_synced_total: int = 0

    # health / connectivity
    reconnected_count: int = 0
    connected_at: datetime | None = None
    disconnected_at: datetime | None = None
