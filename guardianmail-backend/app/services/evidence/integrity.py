"""Forensic integrity + chain-of-custody helpers (Module 9).

Every evidence pack produced by the platform gets:
  * a stable SHA-256 over the canonical JSON manifest,
  * an HMAC-SHA256 signature scoped to the deployment secret,
  * an append-only chain-of-custody log persisted to Mongo,
  * a `verify()` helper the API layer / CLI can call at any time.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.database.mongodb import get_db


CANONICAL_SEPARATORS = (",", ":")


def canonical_json(payload: Any) -> bytes:
    """Deterministic JSON encoding used for hashing/signing."""
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False,
        separators=CANONICAL_SEPARATORS, default=str,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_signature(data: bytes) -> str:
    key = settings.SECRET_KEY.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_signature(data: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_signature(data), signature)


async def record_custody_event(
    pack_id: str,
    *,
    user_id: str,
    event: str,
    actor: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append an immutable chain-of-custody event.

    The `evidence_custody` collection is the canonical audit trail; nothing
    else in the platform writes to it besides this function.
    """
    db = get_db()
    doc = {
        "pack_id": pack_id,
        "user_id": user_id,
        "event": event,
        "actor": actor or user_id,
        "detail": detail or {},
        "at": datetime.now(timezone.utc),
    }
    await db.evidence_custody.insert_one(doc)


async def custody_trail(pack_id: str) -> list[dict[str, Any]]:
    db = get_db()
    cur = db.evidence_custody.find({"pack_id": pack_id}, sort=[("at", 1)])
    return [
        {**d, "_id": str(d["_id"])} async for d in cur
    ]


def integrity_envelope(pack_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
    """Wrap a manifest with hash + signature + timestamp."""
    canonical = canonical_json(manifest)
    return {
        "pack_id": pack_id,
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sha256": sha256_hex(canonical),
        "signature": hmac_signature(canonical),
        "manifest": manifest,
    }


def verify_envelope(envelope: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, reason)."""
    try:
        manifest = envelope["manifest"]
        expected_hash = envelope["sha256"]
        signature = envelope["signature"]
    except KeyError as exc:
        return False, f"missing field {exc}"
    canonical = canonical_json(manifest)
    if sha256_hex(canonical) != expected_hash:
        return False, "sha256 mismatch"
    if not verify_signature(canonical, signature):
        return False, "signature mismatch"
    return True, "ok"
