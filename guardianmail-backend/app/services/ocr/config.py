"""Static configuration for the OCR / Attachment Security engine.

Any constant a service reuses lives here. Keeping thresholds and allow-lists
in one module avoids the drift you get when values are duplicated across
validators, workers, and API handlers.
"""
from __future__ import annotations

# ---- upload limits ----------------------------------------------------------
MAX_UPLOAD_BYTES = 20 * 1024 * 1024          # 20 MiB hard cap
MAX_IMAGE_PIXELS = 40_000_000                 # protects Pillow / OpenCV
MAX_PDF_PAGES = 200
TEXT_STORE_LIMIT = 200_000                    # store at most 200 KB of text
TEXT_TRUNCATE_MARKER = "\n[...truncated by ocr pipeline...]"

# ---- OCR runtime ------------------------------------------------------------
OCR_LANGS = "eng"
OCR_TIMEOUT_S = 60
DEFAULT_DPI = 220

# ---- Allowed MIME / extensions ---------------------------------------------
ALLOWED_IMAGE_MIMES = {
    "image/jpeg", "image/jpg", "image/png", "image/bmp",
    "image/tiff", "image/webp", "image/gif",
}
ALLOWED_DOC_MIMES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain", "text/csv", "application/json", "application/xml",
    "application/zip",
}
ALLOWED_MIMES = ALLOWED_IMAGE_MIMES | ALLOWED_DOC_MIMES

EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "com", "msi", "scr", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "jar", "apk",
    "app", "dmg", "lnk", "reg", "ipa", "sh", "elf",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "cab"}
DOUBLE_EXTENSION_SUSPECTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg",
    "txt", "csv", "html", "htm",
}

# ---- URL shortener list -----------------------------------------------------
KNOWN_SHORTENERS = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "s.id", "adf.ly", "bl.ink", "lnkd.in", "shorte.st", "t.ly",
}

# ---- brand allow-list (used for typosquat scoring) -------------------------
COMMON_BRANDS = {
    "google", "gmail", "microsoft", "outlook", "office365", "apple",
    "icloud", "amazon", "aws", "paypal", "stripe", "netflix", "meta",
    "facebook", "instagram", "whatsapp", "chase", "hsbc", "wellsfargo",
    "citibank", "sbi", "hdfc", "icici", "axis", "flipkart", "linkedin",
    "adobe", "github", "dropbox", "docusign", "zoom",
}

# ---- language cues ---------------------------------------------------------
URGENT_PHRASES = [
    "act now", "urgent", "immediately", "final notice", "last warning",
    "account suspended", "verify your account", "unusual activity",
    "click here to confirm", "limited time", "expires today",
    "payment failed", "security alert", "unauthorised login",
]
CREDENTIAL_PHRASES = [
    "confirm your password", "enter your password", "verify your login",
    "sign in to continue", "one-time password", "otp", "authenticate",
    "reset your password", "verify identity",
]
PAYMENT_PHRASES = [
    "wire transfer", "gift card", "bitcoin", "usdt", "crypto wallet",
    "pay now", "invoice attached", "outstanding balance", "remit payment",
]
INVOICE_PHRASES = [
    "invoice #", "invoice number", "purchase order", "po #", "receipt",
    "billing statement", "tax invoice",
]
