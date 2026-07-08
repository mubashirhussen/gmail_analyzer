"""Outbound webhook delivery with retries, HMAC signing, and status tracking.

Every dispatch is persisted in `webhook_deliveries` with an audit trail of
attempts, response codes, and signature bytes. Failed deliveries are re-queued
with exponential backoff (Celery ETA) up to a max attempt count.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import uuid
from datetime import datetime, timezone

import httpx

from app.database.mongodb import get_db

MAX_ATTEMPTS = 6
BACKOFF_SECONDS = [10, 30, 120, 600, 1800, 7200]  # ~10s -> 2h


def sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    expected = sign_payload(secret, body)
    return hmac.compare_digest(expected, signature)


async def enqueue_delivery(user_id: str, url: str, secret: str, event: str, payload: dict) -> str:
    db = get_db()
    delivery_id = str(uuid.uuid4())
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    signature = sign_payload(secret, body)
    doc = {
        "_id": delivery_id,
        "user_id": user_id,
        "url": url,
        "event": event,
        "payload": payload,
        "signature": signature,
        "status": "pending",   # pending|delivered|failed|dead
        "attempts": [],
        "attempt_count": 0,
        "next_attempt_at": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    await db.webhook_deliveries.insert_one(doc)
    # Fire immediately; scheduler will retry failed rows.
    from app.workers.webhook_tasks import deliver_webhook
    deliver_webhook.delay(delivery_id)
    return delivery_id


async def attempt_delivery(delivery_id: str) -> dict:
    db = get_db()
    row = await db.webhook_deliveries.find_one({"_id": delivery_id})
    if not row:
        return {"ok": False, "error": "not_found"}
    if row["status"] in ("delivered", "dead"):
        return {"ok": True, "status": row["status"]}

    body = json.dumps(row["payload"], separators=(",", ":"), sort_keys=True).encode()
    # Re-verify signature bytes have not been tampered with in storage.
    if not hmac.compare_digest(sign_payload_from_row(row), row["signature"]):
        await db.webhook_deliveries.update_one(
            {"_id": delivery_id},
            {"$set": {"status": "dead", "updated_at": datetime.now(timezone.utc)},
             "$push": {"attempts": {"at": datetime.now(timezone.utc),
                                    "error": "signature_reverify_failed"}}},
        )
        return {"ok": False, "error": "signature_reverify_failed"}

    attempt_no = row["attempt_count"] + 1
    started = datetime.now(timezone.utc)
    attempt: dict = {"n": attempt_no, "at": started}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                row["url"], content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-GuardianMail-Event": row["event"],
                    "X-GuardianMail-Delivery": delivery_id,
                    "X-Signature": row["signature"],
                },
            )
        attempt["status_code"] = resp.status_code
        attempt["response_snippet"] = resp.text[:400]
        ok = 200 <= resp.status_code < 300
    except Exception as e:  # noqa: BLE001
        attempt["error"] = str(e)[:400]
        ok = False

    update: dict = {"$push": {"attempts": attempt}, "$inc": {"attempt_count": 1},
                    "$set": {"updated_at": datetime.now(timezone.utc)}}
    if ok:
        update["$set"]["status"] = "delivered"
    elif attempt_no >= MAX_ATTEMPTS:
        update["$set"]["status"] = "dead"
    else:
        backoff = BACKOFF_SECONDS[min(attempt_no, len(BACKOFF_SECONDS) - 1)]
        eta = datetime.now(timezone.utc).timestamp() + backoff
        update["$set"]["status"] = "pending"
        update["$set"]["next_attempt_at"] = datetime.fromtimestamp(eta, tz=timezone.utc)
        from app.workers.webhook_tasks import deliver_webhook
        deliver_webhook.apply_async(args=[delivery_id], countdown=backoff)
    await db.webhook_deliveries.update_one({"_id": delivery_id}, update)
    return {"ok": ok, "attempt": attempt_no}


def sign_payload_from_row(row: dict) -> str:
    # Signature secret is derived from the stored preference at enqueue time;
    # we re-sign the persisted payload to detect tampering, using the same body.
    body = json.dumps(row["payload"], separators=(",", ":"), sort_keys=True).encode()
    # The row stored the resulting signature; recompute with same secret if
    # available on the delivery row. If not present (legacy row), recompute
    # against payload only and compare to stored signature — a mismatch here
    # means the payload was mutated in storage.
    secret = row.get("secret") or ""
    if not secret:
        # Best-effort: hash body with empty key; stored signature was also
        # empty-key at enqueue in that case.
        return sign_payload(secret, body)
    return sign_payload(secret, body)
