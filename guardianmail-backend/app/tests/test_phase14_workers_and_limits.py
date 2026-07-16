"""Phase 14 — Celery, rate-limit, and repository invariant tests."""
from __future__ import annotations

import pytest


# ---- Celery task graph invariants -------------------------------------
def test_celery_retry_policy_configured():
    from app.workers.celery_app import celery
    ann = celery.conf.task_annotations or {}
    assert ann.get("*", {}).get("max_retries") == 3
    assert celery.conf.task_acks_late is True
    assert celery.conf.task_reject_on_worker_lost is True


def test_dead_letter_queue_declared():
    from app.services.tasks.priority import Q_DEAD_LETTER, ALL_QUEUES
    assert Q_DEAD_LETTER in ALL_QUEUES


def test_all_declared_queues_have_max_priority():
    from app.workers.celery_app import celery
    for q in celery.conf.task_queues:
        args = q.queue_arguments or {}
        assert args.get("x-max-priority") == 9, f"queue {q.name} missing priority"


# ---- Rate-limit primitive ---------------------------------------------
async def test_rate_limiter_allows_then_blocks(redis_stub, monkeypatch):
    from app.utils import rate_limit
    monkeypatch.setattr(rate_limit, "get_redis", lambda: redis_stub)
    key = "test:phase14"
    ok1, remaining1 = await rate_limit.check(key, limit=2, window_s=60)
    ok2, remaining2 = await rate_limit.check(key, limit=2, window_s=60)
    ok3, _ = await rate_limit.check(key, limit=2, window_s=60)
    assert ok1 and ok2 and not ok3
    assert remaining1 == 1 and remaining2 == 0


# ---- Repository invariants --------------------------------------------
def test_repository_collection_names():
    from app.repositories.users import UsersRepository
    from app.repositories.sessions import SessionsRepository
    assert UsersRepository.collection_name == "users"
    assert SessionsRepository.collection_name == "sessions"


def test_repository_model_bindings():
    from app.repositories.users import UsersRepository
    from app.models.user import User
    assert UsersRepository.model is User
