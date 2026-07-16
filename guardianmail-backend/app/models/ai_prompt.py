"""Versioned AI prompt template.

Storing prompts as documents lets us:
* Ship prompt experiments without a code deploy.
* Reproduce a historical AI decision exactly (`prompt_hash` on AIReport).
* Attribute drift/regressions to a specific template revision.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.base import Document


class AIPromptTemplate(Document):
    name: str
    version: str
    role: Literal["system", "user"] = "system"
    body: str
    checksum: str
    active: bool = True
    description: str = ""
    tags: list[str] = Field(default_factory=list)
