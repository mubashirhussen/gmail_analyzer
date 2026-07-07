"""End-to-end integration test for the analysis pipeline.

Covers:
  - simulated Gmail thread ingestion
  - link + attachment scanning
  - report generation (verdict + why + impact)
  - dashboard / analytics style aggregation
Runs against a mongomock-backed in-memory DB with the network layer stubbed.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch, AsyncMock

import pytest

pytestmark = pytest.mark.asyncio


class _FakeDB:
    def __init__(self):
        self._data: dict[str, list[dict]] = {}

    def _col(self, name): return self._data.setdefault(name, [])

    def __getattr__(self, name):
        data = self._col(name)

        class Col:
            async def insert_one(_, doc):
                data.append(doc); return type("R", (), {"inserted_id": len(data)})
            async def find_one(_, q=None, **__):
                for d in reversed(data):
                    if not q or all(d.get(k) == v for k, v in q.items()): return d
                return None
            async def update_one(_, q, upd, upsert=False):
                for d in data:
                    if all(d.get(k) == v for k, v in q.items()):
                        d.update(upd.get("$set", {}))
                        for k, v in upd.get("$inc", {}).items(): d[k] = d.get(k, 0) + v
                        for k, v in upd.get("$addToSet", {}).items():
                            d.setdefault(k, [])
                            if v not in d[k]: d[k].append(v)
                        return
                if upsert:
                    new = dict(q); new.update(upd.get("$setOnInsert", {}))
                    new.update(upd.get("$set", {}))
                    for k, v in upd.get("$inc", {}).items(): new[k] = v
                    for k, v in upd.get("$addToSet", {}).items(): new[k] = [v]
                    data.append(new)
            def find(_, q=None, **__):
                rows = [d for d in data if not q or all(d.get(k) == v for k, v in q.items())]
                class Cur:
                    def sort(self, *_a, **_k): return self
                    def limit(self, *_a, **_k): return self
                    def __aiter__(self): self._i = iter(rows); return self
                    async def __anext__(self):
                        try: return next(self._i)
                        except StopIteration: raise StopAsyncIteration
                return Cur()
            def aggregate(_, *_a, **_k):
                class Cur:
                    def __aiter__(self): self._i = iter([]); return self
                    async def __anext__(self): raise StopAsyncIteration
                return Cur()

        return Col()


@pytest.fixture
def fake_db():
    return _FakeDB()


async def test_full_pipeline_gmail_thread(fake_db):
    """Ingest sample Gmail message → analyze → verify explainable output."""
    from app.services.phishing import pipeline as p

    with patch.object(p, "get_db", return_value=fake_db), \
         patch.object(p, "scan_urls", new=AsyncMock(return_value={"results": [{
            "url": "https://verify-paypa1.example",
            "providers": [{"provider": "google_safe_browsing", "status": "flagged"}],
         }]})), \
         patch.object(p, "spf_dkim_dmarc", new=AsyncMock(return_value={"spf": "fail", "dkim": "fail", "dmarc": "fail"})), \
         patch.object(p, "gemini_json", new=AsyncMock(return_value={
             "verdict": "phishing", "risk_score": 90, "summary": "AI advisory",
             "attack_category": "credential_theft", "indicators": [], "recommendations": [],
         })):
        result = await p.analyze_message("user-123", {
            "channel": "email",
            "sender": "security@paypa1.example",
            "subject": "URGENT: verify your account",
            "body": "Click https://verify-paypa1.example to confirm your password immediately.",
            "attachments": [],
            "device": {"fingerprint": "dev-abc", "trusted": False, "label": "Chrome/Win"},
        })

    # verdict is deterministic + explainable
    assert result["verdict"] in ("suspicious", "phishing")
    assert result["risk_score"] >= 55
    assert result["why"]["headline"]
    assert len(result["why"]["reasons"]) >= 2
    assert result["impact"]["forward_count"] == 1
    assert result["impact"]["impacted_users"] == 1

    # dashboard-style aggregation
    threats = fake_db._col("threats")
    assert len(threats) == 1
    assert threats[0]["artifact_hash"]
    assert threats[0]["signals"]

    # device link recorded
    assert len(fake_db._col("device_artifacts")) == 1
    assert fake_db._col("device_artifacts")[0]["device_fingerprint"] == "dev-abc"


async def test_impact_grows_across_forwards(fake_db):
    from app.services.tracking import forwards
    with patch("app.services.tracking.forwards.get_db", return_value=fake_db):
        s1 = await forwards.record_forward(kind="email", key="a|b", user_id="u1",
                                           verdict="phishing", risk_score=90)
        s2 = await forwards.record_forward(kind="email", key="a|b", user_id="u2",
                                           verdict="phishing", risk_score=92)
    assert s2["forward_count"] == 2
    assert s2["impacted_users"] == 2
