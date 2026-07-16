"""QR-code scanning for images *and* rasterised PDF pages.

Wraps the existing `services.qr.decoder.decode_qr` primitive. Extends it
by:

* rendering PDF pages at DEFAULT_DPI and scanning each rasterised image, and
* classifying payloads into {url, email, phone, upi, payment, wifi, vcard,
  text} so the UI can render the right chip and the Threat Intelligence
  Engine gets URL-only payloads.
"""
from __future__ import annotations

import io
import re
from typing import Iterable

from app.core.logging import get_logger
from app.models.ocr_report import QRResult
from app.services.ocr.config import DEFAULT_DPI, MAX_PDF_PAGES
from app.services.qr.decoder import decode_qr

_log = get_logger(__name__)

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MAILTO = re.compile(r"^mailto:", re.IGNORECASE)
_TEL = re.compile(r"^tel:", re.IGNORECASE)
_UPI = re.compile(r"^upi://", re.IGNORECASE)
_WIFI = re.compile(r"^WIFI:", re.IGNORECASE)
_VCARD = re.compile(r"^BEGIN:VCARD", re.IGNORECASE)


def _classify(payload: str) -> str:
    if _URL_RE.match(payload):
        return "url"
    if _MAILTO.match(payload):
        return "email"
    if _TEL.match(payload):
        return "phone"
    if _UPI.match(payload):
        return "upi"
    if _WIFI.match(payload):
        return "wifi"
    if _VCARD.match(payload):
        return "vcard"
    if any(k in payload.lower() for k in ("pay?", "checkout", "invoice", "payment")):
        return "payment"
    return "text"


def _wrap(codes: Iterable[dict]) -> list[QRResult]:
    out: list[QRResult] = []
    for c in codes:
        payload = c.get("payload") or ""
        if not payload:
            continue
        out.append(QRResult(
            payload=payload,
            type=c.get("type") or "QRCODE",
            is_url=_URL_RE.match(payload) is not None,
            category=_classify(payload),  # type: ignore[arg-type]
        ))
    return out


def scan_image(raw: bytes) -> list[QRResult]:
    try:
        return _wrap(decode_qr(raw))
    except Exception as e:  # pragma: no cover
        _log.warning("qr_scan_image_failed", error=str(e))
        return []


def scan_pdf(raw: bytes) -> list[QRResult]:
    try:
        import fitz  # PyMuPDF
    except Exception:  # pragma: no cover
        return []
    out: list[QRResult] = []
    try:
        with fitz.open(stream=raw, filetype="pdf") as doc:
            for i in range(min(doc.page_count, MAX_PDF_PAGES)):
                page = doc[i]
                pix = page.get_pixmap(dpi=DEFAULT_DPI, alpha=False)
                out.extend(scan_image(pix.tobytes("png")))
    except Exception as e:  # pragma: no cover
        _log.warning("qr_scan_pdf_failed", error=str(e))
    return _dedup(out)


def _dedup(codes: list[QRResult]) -> list[QRResult]:
    seen: dict[str, QRResult] = {}
    for c in codes:
        seen.setdefault(c.payload, c)
    return list(seen.values())


def scan(raw: bytes, mime: str) -> list[QRResult]:
    mime = (mime or "").lower()
    if mime.startswith("image/"):
        return scan_image(raw)
    if mime == "application/pdf":
        return scan_pdf(raw)
    return []
