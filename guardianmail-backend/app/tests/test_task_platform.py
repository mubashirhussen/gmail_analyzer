"""Unit tests for the task platform helpers."""
from __future__ import annotations

from app.services.tasks.priority import (
    ALL_QUEUES, Q_AI, Q_DEFAULT, Q_OCR, TaskPriority, queue_for,
)
from app.services.tasks.retry import (
    DEFAULT_POLICY, RetryPolicy, retry_delay_seconds, should_dead_letter,
)


def test_queue_for_uses_prefix_map():
    assert queue_for("ocr.process_upload") == Q_OCR
    assert queue_for("ai.analyze") == Q_AI
    assert queue_for("unknown.task") == Q_DEFAULT


def test_priority_enum_bounds():
    assert int(TaskPriority.CRITICAL) == 9
    assert int(TaskPriority.BACKGROUND) == 1


def test_all_queues_are_unique():
    assert len(ALL_QUEUES) == len(set(ALL_QUEUES))


def test_retry_delay_grows_and_respects_max():
    p = RetryPolicy(max_retries=5, base_delay_s=10, max_delay_s=120, jitter_ratio=0.0)
    delays = [retry_delay_seconds(i, p) for i in range(0, 6)]
    # non-decreasing until capped
    assert delays[0] <= delays[1] <= delays[2] <= delays[3]
    assert max(delays) <= p.max_delay_s


def test_dead_letter_threshold():
    assert not should_dead_letter(0, DEFAULT_POLICY)
    assert should_dead_letter(DEFAULT_POLICY.max_retries, DEFAULT_POLICY)
