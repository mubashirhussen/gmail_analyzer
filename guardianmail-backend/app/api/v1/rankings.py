"""Rankings — most risky links, domains, emails, QR payloads.

Uses persisted `threats` + `artifact_stats` collections and blends
forward_count, impacted_users, and current risk_score into a composite
"danger index" so the dashboard can show a single sorted list.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query

from app.core.security import require_user
from app.database.mongodb import get_db

router = APIRouter(prefix="/rankings", tags=["rankings"])


def _danger(risk_score: int, forwards: int, impacted: int) -> float:
    # log-scale reach so a viral low-risk item can't outrank a critical rare one
    import math
    return round(risk_score + 8 * math.log1p(forwards) + 12 * math.log1p(impacted), 2)


async def _top(db, kind: str, limit: int) -> list[dict]:
    cur = db.artifact_stats.find({"kind": kind}).limit(500)
    rows = [r async for r in cur]
    for r in rows:
        r["danger_index"] = _danger(
            int(r.get("last_risk_score", 0)),
            int(r.get("forward_count", 0)),
            int(r.get("impacted_users", 0)),
        )
    rows.sort(key=lambda r: r["danger_index"], reverse=True)
    return rows[:limit]


@router.get("/links")
async def top_links(limit: int = Query(20, le=100), _=Depends(require_user), db=Depends(get_db)):
    return {"items": await _top(db, "link", limit)}


@router.get("/domains")
async def top_domains(limit: int = Query(20, le=100), _=Depends(require_user), db=Depends(get_db)):
    rows = await _top(db, "link", 500)
    agg: dict[str, dict] = {}
    for r in rows:
        host = urlparse(r.get("key", "")).netloc or r.get("key", "")
        a = agg.setdefault(host, {"domain": host, "forward_count": 0,
                                  "impacted_users": 0, "last_risk_score": 0})
        a["forward_count"] += int(r.get("forward_count", 0))
        a["impacted_users"] += int(r.get("impacted_users", 0))
        a["last_risk_score"] = max(a["last_risk_score"], int(r.get("last_risk_score", 0)))
    out = list(agg.values())
    for a in out:
        a["danger_index"] = _danger(a["last_risk_score"], a["forward_count"], a["impacted_users"])
    out.sort(key=lambda r: r["danger_index"], reverse=True)
    return {"items": out[:limit]}


@router.get("/emails")
async def top_emails(limit: int = Query(20, le=100), _=Depends(require_user), db=Depends(get_db)):
    return {"items": await _top(db, "email", limit)}


@router.get("/qr")
async def top_qr(limit: int = Query(20, le=100), _=Depends(require_user), db=Depends(get_db)):
    return {"items": await _top(db, "qr", limit)}
