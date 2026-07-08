"""Real-time audit & security alert streaming via Server-Sent Events.

Uses Redis pub/sub so multiple API workers can fan out events. Producers call
`publish_event()`; the SSE endpoint subscribes per user_id channel.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.core.security import decode_token
from app.database.redis import get_redis

router = APIRouter(prefix="/stream", tags=["stream"])

CH_PREFIX = "alerts:"


async def publish_event(user_id: str, event: str, data: dict) -> None:
    r = get_redis()
    payload = json.dumps({
        "event": event,
        "data": data,
        "at": datetime.now(timezone.utc).isoformat(),
    })
    await r.publish(f"{CH_PREFIX}{user_id}", payload)


def _auth_from_query(token: str) -> dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise ValueError("wrong token type")
    return payload


@router.get("/alerts")
async def stream_alerts(token: str = Query(..., description="access JWT (SSE can't set headers)")):
    user = _auth_from_query(token)
    user_id = user["sub"]

    async def event_gen():
        r = get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(f"{CH_PREFIX}{user_id}")
        yield f": connected {datetime.now(timezone.utc).isoformat()}\n\n"
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15)
                if msg is None:
                    yield ": keepalive\n\n"
                    continue
                data = msg.get("data")
                if isinstance(data, bytes):
                    data = data.decode()
                try:
                    parsed = json.loads(data)
                    event_name = parsed.get("event", "alert")
                except Exception:  # noqa: BLE001
                    event_name = "alert"
                yield f"event: {event_name}\ndata: {data}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await pubsub.unsubscribe(f"{CH_PREFIX}{user_id}")
            await pubsub.close()

    return StreamingResponse(event_gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })
