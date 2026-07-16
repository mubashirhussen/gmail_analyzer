"""Application container — lazy singletons wired at startup.

Kept intentionally small; feature modules register their services here
so API routes resolve them via `Depends(get_container)`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AppContainer:
    services: dict[str, Any] = field(default_factory=dict)

    def register(self, name: str, instance: Any) -> None:
        self.services[name] = instance

    def get(self, name: str) -> Any:
        if name not in self.services:
            raise KeyError(f"service '{name}' not registered")
        return self.services[name]


_container = AppContainer()


def get_container() -> AppContainer:
    return _container
