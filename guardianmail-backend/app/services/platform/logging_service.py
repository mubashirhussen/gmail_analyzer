"""Structured logging helper (Module 11).

Thin wrapper around structlog so business modules don't need to import
structlog directly; also enforces a stable event vocabulary for auditing.
"""
from __future__ import annotations

from typing import Any

import structlog


class LoggingService:
    def __init__(self, name: str = "guardianmail") -> None:
        self._log = structlog.get_logger(name)

    def event(self, name: str, **fields: Any) -> None:
        self._log.info(name, **fields)

    def warn(self, name: str, **fields: Any) -> None:
        self._log.warning(name, **fields)

    def error(self, name: str, **fields: Any) -> None:
        self._log.error(name, **fields)


logging_service = LoggingService()
