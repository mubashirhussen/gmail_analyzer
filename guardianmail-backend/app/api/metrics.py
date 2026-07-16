"""Prometheus scrape endpoint.

Mounted at `/metrics` alongside the health probes. Access is gated behind
a shared secret so external scrapers hit it but random callers can't.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Header, HTTPException, Response

from app.core.metrics import render

router = APIRouter(tags=["meta"])


@router.get("/metrics")
async def metrics(x_metrics_token: str | None = Header(default=None)) -> Response:
    token = os.environ.get("METRICS_TOKEN")
    if token and x_metrics_token != token:
        raise HTTPException(status_code=403, detail="forbidden")
    body, content_type = render()
    return Response(content=body, media_type=content_type)
