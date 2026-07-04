"""OCR — PaddleOCR primary, Tesseract fallback, PDF text extraction."""
from __future__ import annotations

import io

from PIL import Image
import pytesseract

try:
    from paddleocr import PaddleOCR
    _paddle: PaddleOCR | None = PaddleOCR(use_angle_cls=True, lang="en", show_log=False)
except Exception:  # noqa: BLE001 - paddle is optional
    _paddle = None


async def extract_text(raw: bytes, mime: str) -> str:
    if mime.startswith("application/pdf"):
        return _pdf_text(raw)
    if mime.startswith("image/"):
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        if _paddle is not None:
            try:
                lines = _paddle.ocr(_pil_to_np(img), cls=True)
                return "\n".join(x[1][0] for page in lines or [] for x in (page or []))
            except Exception:
                pass
        return pytesseract.image_to_string(img)
    if mime.startswith("text/") or mime in {"application/json", "application/xml"}:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


def _pdf_text(raw: bytes) -> str:
    from pypdf import PdfReader
    r = PdfReader(io.BytesIO(raw))
    return "\n".join((p.extract_text() or "") for p in r.pages[:50])


def _pil_to_np(img):
    import numpy as np
    return np.array(img)
