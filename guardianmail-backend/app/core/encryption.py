"""AES-GCM helper for at-rest secrets (Gmail refresh tokens, etc.)."""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


def _key() -> bytes:
    raw = settings.FERNET_KEY.encode() if settings.FERNET_KEY else settings.SECRET_KEY.encode()
    # normalise to 32 bytes
    return (raw + b"\x00" * 32)[:32]


def encrypt(plaintext: str) -> str:
    aes = AESGCM(_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode())
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(_key()).decrypt(nonce, ct, None).decode()
