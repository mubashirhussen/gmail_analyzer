"""Filename / MIME / size validation gate.

Runs before any bytes are decoded. Rejecting here is cheap and stops the
downstream pipeline from ever touching hostile input beyond a hash + size
check. Every rejection returns a stable error code the API can map to a
user-facing message.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from app.core.exceptions import DomainError
from app.services.ocr.config import (
    ALLOWED_MIMES, ARCHIVE_EXTENSIONS, DOUBLE_EXTENSION_SUSPECTS,
    EXECUTABLE_EXTENSIONS, MAX_UPLOAD_BYTES,
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\- ]+")


class OCRValidationError(DomainError):
    status_code = 415
    code = "ocr_validation_failed"


@dataclass(slots=True)
class ValidatedUpload:
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    double_extension: bool
    is_executable: bool
    is_archive: bool


def sanitize_filename(raw: str) -> str:
    """Strip path components and unsafe chars — never trust client input."""
    base = os.path.basename(raw or "").strip() or "attachment"
    base = _SAFE_NAME.sub("_", base)
    return base[:255]


def _split_extension(name: str) -> tuple[str, bool]:
    parts = name.lower().rsplit(".", 2)
    if len(parts) >= 3 and parts[-2] in DOUBLE_EXTENSION_SUSPECTS:
        return parts[-1], True
    if len(parts) >= 2:
        return parts[-1], False
    return "", False


def validate_upload(filename: str, mime_type: str, size_bytes: int) -> ValidatedUpload:
    clean = sanitize_filename(filename)
    if size_bytes <= 0:
        raise OCRValidationError("empty upload", code="ocr_empty_upload")
    if size_bytes > MAX_UPLOAD_BYTES:
        raise OCRValidationError(
            f"file exceeds {MAX_UPLOAD_BYTES} bytes",
            code="ocr_file_too_large",
            details={"max_bytes": MAX_UPLOAD_BYTES, "size": size_bytes},
        )

    mime = (mime_type or "application/octet-stream").split(";")[0].strip().lower()
    if mime not in ALLOWED_MIMES:
        raise OCRValidationError(
            f"unsupported mime type: {mime}",
            code="ocr_unsupported_mime",
            details={"mime_type": mime},
        )

    ext, double = _split_extension(clean)
    return ValidatedUpload(
        filename=clean,
        extension=ext,
        mime_type=mime,
        size_bytes=size_bytes,
        double_extension=double,
        is_executable=ext in EXECUTABLE_EXTENSIONS,
        is_archive=ext in ARCHIVE_EXTENSIONS,
    )
