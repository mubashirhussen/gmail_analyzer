"""Base service class. Services orchestrate repositories and external I/O."""
from __future__ import annotations

import structlog


class BaseService:
    def __init__(self) -> None:
        self.log = structlog.get_logger(self.__class__.__name__)
