"""Document-level metadata extraction (author, producer, embedded links)."""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime

from app.core.logging import get_logger
from app.models.ocr_report import DocumentMetadata

_log = get_logger(__name__)

_PDF_DATE = re.compile(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?")


def _parse_pdf_date(v: str | None) -> datetime | None:
    if not v:
        return None
    m = _PDF_DATE.match(v)
    if not m:
        return None
    parts = [int(g) if g else 0 for g in m.groups()]
    try:
        return datetime(parts[0], parts[1] or 1, parts[2] or 1,
                        parts[3], parts[4], parts[5])
    except ValueError:
        return None


def extract(filename: str, ext: str, mime: str, size: int, raw: bytes) -> DocumentMetadata:
    md = DocumentMetadata(filename=filename, extension=ext, size_bytes=size, mime_type=mime)
    try:
        if mime == "application/pdf":
            _pdf(md, raw)
        elif mime in {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }:
            _office(md, raw)
        elif mime.startswith("image/"):
            _image(md, raw)
    except Exception as e:  # pragma: no cover
        _log.warning("metadata_extract_failed", mime=mime, error=str(e))
    return md


# ---------------------------------------------------------------- pdf -------
def _pdf(md: DocumentMetadata, raw: bytes) -> None:
    try:
        import fitz  # PyMuPDF
        with fitz.open(stream=raw, filetype="pdf") as doc:
            meta = doc.metadata or {}
            md.author = meta.get("author") or None
            md.creator = meta.get("creator") or None
            md.producer = meta.get("producer") or None
            md.software = meta.get("producer") or meta.get("creator") or None
            md.doc_created_at = _parse_pdf_date(meta.get("creationDate"))
            md.doc_modified_at = _parse_pdf_date(meta.get("modDate"))
            md.page_count = doc.page_count
            links: list[str] = []
            embedded: list[str] = []
            for page in doc:
                for link in page.get_links() or []:
                    if link.get("uri"):
                        links.append(link["uri"])
            try:
                for i in range(doc.embfile_count()):
                    info = doc.embfile_info(i)
                    embedded.append(info.get("filename", f"file_{i}"))
            except Exception:
                pass
            md.embedded_links = list(dict.fromkeys(links))[:200]
            md.embedded_files = embedded[:50]
        return
    except Exception:
        pass
    # fallback to pypdf metadata
    try:
        from pypdf import PdfReader
        r = PdfReader(io.BytesIO(raw))
        info = r.metadata or {}
        md.author = getattr(info, "author", None)
        md.creator = getattr(info, "creator", None)
        md.producer = getattr(info, "producer", None)
        md.page_count = len(r.pages)
    except Exception:  # pragma: no cover
        return


# --------------------------------------------------------------- office -----
def _office(md: DocumentMetadata, raw: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = z.namelist()
            md.extra["parts"] = len(names)
            if "docProps/core.xml" in names:
                with z.open("docProps/core.xml") as f:
                    xml = f.read().decode("utf-8", errors="replace")
                    md.author = _tag(xml, "dc:creator") or md.author
                    md.creator = _tag(xml, "cp:lastModifiedBy") or md.creator
            if "docProps/app.xml" in names:
                with z.open("docProps/app.xml") as f:
                    xml = f.read().decode("utf-8", errors="replace")
                    md.software = _tag(xml, "Application") or md.software
            md.embedded_files = [n for n in names if n.startswith(("word/embeddings/", "xl/embeddings/"))][:50]
    except Exception:  # pragma: no cover
        return


def _tag(xml: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xml)
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------- image -----
def _image(md: DocumentMetadata, raw: bytes) -> None:
    try:
        from PIL import Image, ExifTags
        img = Image.open(io.BytesIO(raw))
        md.extra["format"] = img.format
        md.extra["mode"] = img.mode
        md.extra["size"] = list(img.size)
        exif = getattr(img, "_getexif", lambda: None)() or {}
        for tag_id, value in exif.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name in {"Software", "Make", "Model", "DateTime"}:
                md.extra[f"exif_{name.lower()}"] = str(value)[:200]
        md.software = md.extra.get("exif_software")
    except Exception:  # pragma: no cover
        return
