"""Attachment metadata analysis.

The engine never fetches attachment bytes — that is a downstream Module
(OCR / sandbox). Here we look at the metadata Gmail sync already
persisted: filename, extension, MIME, size, and any hash Gmail
exposed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.services.threat.config import (
    ARCHIVE_EXTS,
    EXECUTABLE_EXTS,
    OFFICE_MACRO_EXTS,
)


@dataclass(slots=True)
class AttachmentIndicator:
    category: str
    severity: str
    detail: str
    filename: str
    evidence: dict


# A curated seed list of hashes seen in confirmed campaigns. Extended
# at runtime from feeds (Module 7).
_KNOWN_MALWARE_HASHES: set[str] = set()


def _extension(name: str) -> str:
    if not name or "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower().strip()


def _double_extension(name: str) -> str | None:
    parts = name.lower().split(".")
    if len(parts) < 3:
        return None
    inner, outer = parts[-2], parts[-1]
    if inner in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"} \
            and outer in EXECUTABLE_EXTS:
        return f".{inner}.{outer}"
    return None


class AttachmentAnalysisService:
    def analyze(self, attachments: Iterable[dict]) -> list[AttachmentIndicator]:
        out: list[AttachmentIndicator] = []
        for att in attachments or []:
            name = (att.get("filename") or "").strip()
            mime = (att.get("mime_type") or "").lower()
            size = int(att.get("size") or 0)
            sha256 = (att.get("sha256") or "").lower() or None
            ext = _extension(name)

            if not name:
                continue

            if dbl := _double_extension(name):
                out.append(AttachmentIndicator(
                    "double_extension", "high",
                    f"Attachment '{name}' uses double extension {dbl}.",
                    name, {"ext": ext, "double": dbl},
                ))
            if ext in EXECUTABLE_EXTS:
                out.append(AttachmentIndicator(
                    "executable_attachment", "critical",
                    f"Attachment '{name}' is an executable ({ext}).",
                    name, {"ext": ext, "mime": mime, "size": size},
                ))
            if ext in OFFICE_MACRO_EXTS:
                out.append(AttachmentIndicator(
                    "macro_office_document", "high",
                    f"Macro-enabled Office document '{name}' — commonly used for droppers.",
                    name, {"ext": ext, "mime": mime},
                ))
            if ext in ARCHIVE_EXTS:
                encrypted = bool(att.get("encrypted"))
                severity = "high" if encrypted else "low"
                out.append(AttachmentIndicator(
                    "encrypted_archive" if encrypted else "archive_attachment",
                    severity,
                    ("Password-protected archive — bypasses most gateway scanners."
                     if encrypted else f"Archive attachment ({ext})."),
                    name, {"ext": ext, "encrypted": encrypted, "size": size},
                ))
            if mime == "application/octet-stream" and ext not in EXECUTABLE_EXTS:
                out.append(AttachmentIndicator(
                    "opaque_mime", "low",
                    f"Attachment '{name}' declared as application/octet-stream (opaque).",
                    name, {"ext": ext},
                ))
            if sha256 and sha256 in _KNOWN_MALWARE_HASHES:
                out.append(AttachmentIndicator(
                    "known_malware_hash", "critical",
                    f"Attachment SHA-256 matches a known malware sample.",
                    name, {"sha256": sha256},
                ))
        return out


attachment_analysis_service = AttachmentAnalysisService()
