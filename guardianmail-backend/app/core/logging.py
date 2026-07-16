"""Structured logging setup — structlog on top of stdlib.

- JSON in prod/staging, colored key/value in dev.
- Auto-binds request_id / user_id / path from `app.core.context`.
- Redacts obvious secrets in event kwargs.
- Rotates file logs under `logs/app.log` when LOG_TO_FILE=1.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any

import structlog

from app.core import context
from app.core.config import settings


_REDACT_KEYS = {
    "password", "passwd", "secret", "token", "authorization",
    "cookie", "set-cookie", "refresh_token", "access_token",
    "fernet_key", "api_key", "client_secret",
}


def _redactor(_, __, event_dict: dict[str, Any]) -> dict[str, Any]:
    for k in list(event_dict.keys()):
        if k.lower() in _REDACT_KEYS:
            event_dict[k] = "***"
    return event_dict


def _bind_request_ctx(_, __, event_dict: dict[str, Any]) -> dict[str, Any]:
    ctx = context.get()
    for k, v in (
        ("request_id", ctx.request_id),
        ("user_id", ctx.user_id),
        ("device_id", ctx.device_id),
        ("path", ctx.path),
        ("method", ctx.method),
    ):
        if v and k not in event_dict:
            event_dict[k] = v
    return event_dict


def configure_logging() -> None:
    level = getattr(logging, settings.LOG_LEVEL, logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if os.getenv("LOG_TO_FILE") == "1":
        Path("logs").mkdir(exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            "logs/app.log", maxBytes=10_000_000, backupCount=5, encoding="utf-8"
        )
        handlers.append(fh)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=handlers,
        force=True,
    )
    for noisy in ("uvicorn.access", "pymongo", "motor", "asyncio"):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))

    processors: list = [
        structlog.contextvars.merge_contextvars,
        _bind_request_ctx,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redactor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.LOG_JSON:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )


log = structlog.get_logger("guardianmail")
