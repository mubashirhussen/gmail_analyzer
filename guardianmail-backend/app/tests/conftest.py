"""Pytest fixtures — foundation only.

Business modules layer their own fixtures on top; this file provides
`settings_override`, an in-memory MongoDB (mongomock-motor when
available; falls back to a live Atlas/URI), a fake Redis, and a TestClient.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings():
    # Tests should run against APP_ENV=test — enforced at boot.
    settings.APP_ENV = "test"
    return settings


@pytest.fixture()
def client(test_settings) -> Iterator[TestClient]:
    from app.main import app  # imported late so settings override applies
    with TestClient(app) as c:
        yield c


@pytest.fixture()
async def redis_stub() -> AsyncIterator[object]:
    try:
        import fakeredis.aioredis as fake  # type: ignore
        r = fake.FakeRedis(decode_responses=True)
    except ImportError:  # pragma: no cover - optional dep
        pytest.skip("fakeredis not installed")
    try:
        yield r
    finally:
        await r.aclose()
