"""Image enhancement for OCR — best-effort, deps degrade gracefully.

The pipeline is intentionally light: greyscale → denoise → deskew → adaptive
threshold. That combination lifts Tesseract accuracy on scanned invoices
without exploding CPU. If OpenCV isn't installed we fall back to Pillow,
which still handles rotation via EXIF and simple contrast.
"""
from __future__ import annotations

import io

from PIL import Image, ImageOps

try:  # optional, deployed on OCR workers only
    import cv2  # type: ignore
    import numpy as np  # type: ignore
    _HAS_CV = True
except Exception:  # pragma: no cover
    cv2 = None  # type: ignore
    np = None  # type: ignore
    _HAS_CV = False


def _load(raw: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(raw))
    img = ImageOps.exif_transpose(img)
    return img.convert("RGB")


def enhance(raw: bytes) -> bytes:
    """Return preprocessed PNG bytes suitable for OCR."""
    img = _load(raw)
    if not _HAS_CV:
        img = ImageOps.grayscale(img)
        img = ImageOps.autocontrast(img, cutoff=2)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    arr = np.array(img)
    gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
    gray = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)
    gray = _deskew(gray)
    gray = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 15
    )
    ok, out = cv2.imencode(".png", gray)
    if not ok:
        raise RuntimeError("cv2 encode failed")
    return out.tobytes()


def _deskew(gray):  # type: ignore[no-untyped-def]
    coords = np.column_stack(np.where(gray < 200))
    if len(coords) < 100:
        return gray
    angle = cv2.minAreaRect(coords)[-1]
    angle = -(90 + angle) if angle < -45 else -angle
    if abs(angle) < 0.5:
        return gray
    h, w = gray.shape
    m = cv2.getRotationMatrix2D((w // 2, h // 2), angle, 1.0)
    return cv2.warpAffine(gray, m, (w, h), flags=cv2.INTER_CUBIC,
                          borderMode=cv2.BORDER_REPLICATE)
