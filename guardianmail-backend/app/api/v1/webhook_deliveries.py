"""Webhook delivery inspection & manual retry API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import require_user
from app.database.mongodb import get_db
from app.services.webhooks.delivery import attempt_delivery

router = APIRouter(prefix="/webhook-deliveries", tags=["webhooks"])


@router.get("")
async def list_deliveries(
    user=Depends(require_user),
    status: str | None = Query(default=None, pattern="^(pending|delivered|failed|dead)$"),
    limit: int = 50,
    db=Depends(get_db),
):
    q: dict = {"user_id": user["sub"]}
    if status:
        q["status"] = status
    cur = db.webhook_deliveries.find(q).sort("created_at", -1).limit(min(limit, 200))
    return {"items": [d async for d in cur]}


@router.get("/{delivery_id}")
async def get_delivery(delivery_id: str, user=Depends(require_user), db=Depends(get_db)):
    row = await db.webhook_deliveries.find_one({"_id": delivery_id, "user_id": user["sub"]})
    if not row:
        raise HTTPException(404, "not found")
    return row


@router.post("/{delivery_id}/retry")
async def retry_delivery(delivery_id: str, user=Depends(require_user), db=Depends(get_db)):
    row = await db.webhook_deliveries.find_one({"_id": delivery_id, "user_id": user["sub"]})
    if not row:
        raise HTTPException(404, "not found")
    if row["status"] == "delivered":
        return {"ok": True, "status": "delivered"}
    return await attempt_delivery(delivery_id)
