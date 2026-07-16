"""Attachment security analysis — structural risk flags on the file itself."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile

from app.models.ocr_report import AttachmentAnalysis
from app.services.ocr.config import ARCHIVE_EXTENSIONS, EXECUTABLE_EXTENSIONS
from app.services.ocr.validation import ValidatedUpload

_MACRO_MARKERS = (b"vbaProject.bin", b"macros/", b"VBA/")
_ENCRYPTED_MARKER = b"EncryptedPackage"
_URL_IN_BINARY = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+")


def analyze(raw: bytes, vu: ValidatedUpload) -> AttachmentAnalysis:
    digest = hashlib.sha256(raw).hexdigest()

    analysis = AttachmentAnalysis(
        filename=vu.filename,
        extension=vu.extension,
        mime_type=vu.mime_type,
        size_bytes=vu.size_bytes,
        sha256=digest,
        double_extension=vu.double_extension,
        is_executable=vu.is_executable,
        is_archive=vu.is_archive,
    )

    macros, encrypted, embedded, links = _inspect(raw, vu)
    analysis.contains_macros = macros
    analysis.is_encrypted = encrypted
    analysis.embedded_objects = embedded
    analysis.hyperlinks = links[:200]

    flags: list[str] = []
    if vu.double_extension:
        flags.append("double_extension")
    if vu.extension in EXECUTABLE_EXTENSIONS:
        flags.append("executable_extension")
    if vu.extension in ARCHIVE_EXTENSIONS:
        flags.append("archive")
    if macros:
        flags.append("contains_macros")
    if encrypted:
        flags.append("password_protected")
    if embedded > 5:
        flags.append("many_embedded_objects")
    if vu.filename.startswith("."):
        flags.append("hidden_name")
    analysis.risk_flags = flags
    return analysis


def _inspect(raw: bytes, vu: ValidatedUpload) -> tuple[bool, bool, int, list[str]]:
    macros = False
    encrypted = False
    embedded = 0
    links: list[str] = []

    # office documents are zip containers — inspect member list
    if vu.extension in {"docx", "xlsx", "pptx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                names = z.namelist()
                macros = any(n.lower().endswith("vbaproject.bin") or "/macros/" in n.lower() for n in names)
                embedded = sum(1 for n in names if "/embeddings/" in n.lower() or "/media/" in n.lower())
                for n in names:
                    if n.endswith(".xml") or n.endswith(".rels"):
                        try:
                            with z.open(n) as f:
                                data = f.read()
                            links.extend(m.decode("utf-8", "replace") for m in _URL_IN_BINARY.findall(data))
                        except Exception:
                            continue
        except zipfile.BadZipFile:
            encrypted = _ENCRYPTED_MARKER in raw[:8192]

    elif vu.extension in {"doc", "xls", "ppt"}:
        # legacy OLE — cheap heuristic
        macros = any(m in raw[:65536].lower() for m in (b"vba", b"macros"))
        encrypted = b"EncryptedPackage" in raw[:8192]

    elif vu.extension == "pdf":
        macros = b"/JS" in raw or b"/JavaScript" in raw
        encrypted = b"/Encrypt" in raw
        try:
            import fitz
            with fitz.open(stream=raw, filetype="pdf") as doc:
                try:
                    embedded = doc.embfile_count()
                except Exception:
                    embedded = 0
                for page in doc:
                    for link in page.get_links() or []:
                        if link.get("uri"):
                            links.append(link["uri"])
        except Exception:
            pass

    elif vu.is_archive:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                encrypted = any(i.flag_bits & 0x1 for i in z.infolist())
                embedded = len(z.infolist())
        except Exception:
            pass

    return macros, encrypted, embedded, list(dict.fromkeys(links))
