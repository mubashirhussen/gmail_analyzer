"""Backwards-compatible shim.

The real orchestration lives in ``app.services.gmail.sync_service``. Kept
so any legacy import of ``app.services.gmail.sync:sync_user`` keeps working
without editing call sites.
"""
from __future__ import annotations

from app.services.gmail.sync_service import gmail_sync_service, sync_user

__all__ = ["gmail_sync_service", "sync_user"]
