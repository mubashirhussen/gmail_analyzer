"""License key + seat management (Phase 20)."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class LicenseService:
    def __init__(self, repository=None):
        self.repo = repository

    def build(self, *, tenant_id: str, subscription_id: str, seats: int,
              duration_days: int = 365) -> dict:
        if seats < 1:
            raise ValueError("seats must be >= 1")
        if duration_days < 1:
            raise ValueError("duration_days must be >= 1")
        now = datetime.now(timezone.utc)
        raw_key = "-".join(
            secrets.token_hex(4).upper() for _ in range(4)
        )
        return {
            "license_id": f"lic_{uuid.uuid4().hex[:20]}",
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "key": raw_key,               # returned to admin ONCE
            "key_hash": _hash(raw_key),   # stored
            "seats": seats,
            "assigned_user_ids": [],
            "status": "issued",
            "issued_at": now,
            "activated_at": None,
            "expires_at": now + timedelta(days=duration_days),
        }

    def activate(self, license_: dict) -> dict:
        if license_.get("status") == "revoked":
            raise ValueError("cannot activate a revoked license")
        license_["status"] = "active"
        license_["activated_at"] = datetime.now(timezone.utc)
        return license_

    def assign_seats(self, license_: dict, user_ids: Iterable[str]) -> dict:
        current = set(license_.get("assigned_user_ids") or [])
        for uid in user_ids:
            if not uid:
                continue
            if uid in current:
                continue
            if len(current) >= int(license_.get("seats", 0)):
                raise ValueError("no available seats")
            current.add(uid)
        license_["assigned_user_ids"] = sorted(current)
        return license_

    def release_seat(self, license_: dict, user_id: str) -> dict:
        license_["assigned_user_ids"] = [
            u for u in (license_.get("assigned_user_ids") or []) if u != user_id
        ]
        return license_

    def revoke(self, license_: dict) -> dict:
        license_["status"] = "revoked"
        license_["revoked_at"] = datetime.now(timezone.utc)
        return license_

    @staticmethod
    def available_seats(license_: dict) -> int:
        return max(int(license_.get("seats", 0))
                   - len(license_.get("assigned_user_ids") or []), 0)

    @staticmethod
    def is_expired(license_: dict, *, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        exp = license_.get("expires_at")
        return bool(exp and exp <= now)

    @staticmethod
    def verify_key(license_: dict, raw_key: str) -> bool:
        return _hash(raw_key or "") == license_.get("key_hash")
