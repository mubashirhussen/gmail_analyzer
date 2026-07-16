"""Exponential backoff retry helper (Module 11)."""
from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, Iterable, TypeVar

import structlog

log = structlog.get_logger(__name__)

T = TypeVar("T")


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 0.25,
    max_delay: float = 5.0,
    retry_on: Iterable[type[BaseException]] = (Exception,),
    name: str = "retry",
) -> T:
    tried = 0
    exc: BaseException | None = None
    while tried < attempts:
        tried += 1
        try:
            return await fn()
        except tuple(retry_on) as e:  # type: ignore[misc]
            exc = e
            if tried >= attempts:
                break
            delay = min(max_delay, base_delay * (2 ** (tried - 1)))
            delay = delay * (0.5 + random.random() / 2)  # jitter
            log.warning("retry", name=name, attempt=tried, delay_s=round(delay, 3), err=str(e))
            await asyncio.sleep(delay)
    assert exc is not None
    raise exc
