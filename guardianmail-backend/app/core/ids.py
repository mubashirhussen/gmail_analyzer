"""ID generators (request ids, trace ids, opaque tokens)."""
from __future__ import annotations

import secrets
import uuid


def uuid_str() -> str:
    return str(uuid.uuid4())


def request_id() -> str:
    return uuid.uuid4().hex[:16]


def opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
