"""Content-hashing helpers used by community reporting + dedup."""
import hashlib
import re


_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def content_hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(normalize(p).encode())
        h.update(b"\x1f")
    return h.hexdigest()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def artifact_hash(kind: str, key: str) -> str:
    """Stable hash for an artifact (link, email, qr) so we can dedupe across users."""
    return content_hash(kind, key)

