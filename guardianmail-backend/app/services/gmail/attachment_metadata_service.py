"""AttachmentMetadataService — extract per-attachment metadata.

We deliberately never persist attachment *contents* here. Bytes are only
fetched on-demand by the OCR / scan pipeline. This service produces the
metadata slice stored on ``EmailDoc.attachments``.
"""
from __future__ import annotations

import mimetypes
import os
from typing import Any

from app.models.email import AttachmentMeta


class AttachmentMetadataService:
    def extract(self, payload: dict[str, Any]) -> list[AttachmentMeta]:
        out: list[AttachmentMeta] = []
        self._walk(payload, out)
        return out

    def _walk(self, part: dict[str, Any], out: list[AttachmentMeta]) -> None:
        if not part:
            return
        body = part.get("body") or {}
        filename = part.get("filename") or None
        if body.get("attachmentId") or (filename and filename.strip()):
            mime = part.get("mimeType") or mimetypes.guess_type(filename or "")[0]
            ext = None
            if filename:
                _, ext = os.path.splitext(filename)
                ext = ext.lstrip(".").lower() or None
            out.append(AttachmentMeta(
                filename=filename,
                extension=ext,
                mime=mime,
                size=int(body.get("size") or 0),
                attachment_id=body.get("attachmentId"),
                stored=False,
                scan_status="pending",
            ))
        for child in part.get("parts") or []:
            self._walk(child, out)


attachment_metadata_service = AttachmentMetadataService()
