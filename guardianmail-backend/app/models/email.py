from datetime import datetime
from pydantic import BaseModel


class EmailDoc(BaseModel):
    user_id: str
    gmail_id: str | None = None
    thread_id: str | None = None
    sender: str
    recipients: list[str] = []
    subject: str = ""
    snippet: str = ""
    body_text: str = ""
    body_html: str | None = None
    labels: list[str] = []
    has_attachments: bool = False
    attachments: list[dict] = []  # [{name, mime, size, sha256}]
    urls: list[str] = []
    received_at: datetime
    analysis_status: str = "pending"  # pending|running|done|error
    threat_id: str | None = None
