"""Schemas for the Gmail integration endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class GmailConnectStartIn(BaseModel):
    redirect_uri: str | None = None


class GmailConnectStartOut(BaseModel):
    authorize_url: str
    state: str


class GmailConnectCallbackIn(BaseModel):
    code: str = Field(min_length=8)
    state: str = Field(min_length=8)


class GmailConnectionOut(BaseModel):
    id: str
    email: EmailStr
    status: str
    scopes: list[str]
    initial_import_completed: bool
    messages_synced_total: int
    history_id: str | None = None
    last_sync_started_at: datetime | None = None
    last_sync_finished_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    connected_at: datetime | None = None


class GmailSyncTriggerIn(BaseModel):
    kind: Literal["manual", "initial", "incremental", "resume"] = "manual"
    async_mode: bool = True


class GmailSyncTriggerOut(BaseModel):
    accepted: bool
    task_id: str | None = None
    status: str
    detail: dict[str, Any] | None = None


class GmailStatusOut(BaseModel):
    connected: bool
    email: EmailStr | None = None
    status: str | None = None
    history_id: str | None = None
    initial_import_completed: bool | None = None
    messages_synced_total: int | None = None
    last_success_at: datetime | None = None
    last_sync_started_at: datetime | None = None
    last_sync_finished_at: datetime | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None
    recent_runs: list[dict[str, Any]] = []


class SyncLogOut(BaseModel):
    id: str
    kind: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None
    messages_scanned: int
    messages_ingested: int
    messages_updated: int
    messages_skipped: int
    api_calls: int
    error_code: str | None = None
    error_message: str | None = None
