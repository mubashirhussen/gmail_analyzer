"""QR-code decoding. Extracts every URL/text payload from an image."""
from __future__ import annotations

import io
from typing import Any

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as zbar_decode
except Exception:  # pragma: no cover — deps installed via requirements.txt
    Image = None
    zbar_decode = None


def decode_qr(image_bytes: bytes) -> list[dict[str, Any]]:
    """Return a list of {payload, type, is_url} decoded from the image."""
    if Image is None or zbar_decode is None:
        return []
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    out: list[dict[str, Any]] = []
    for r in zbar_decode(img):
        try:
            payload = r.data.decode("utf-8", errors="replace")
        except Exception:
            payload = ""
        if not payload:
            continue
        out.append({
            "payload": payload,
            "type": r.type,
            "is_url": payload.lower().startswith(("http://", "https://")),
        })
    return out
