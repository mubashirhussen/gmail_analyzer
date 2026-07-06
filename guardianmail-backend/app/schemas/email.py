from datetime import datetime
from pydantic import BaseModel


class AttachmentIn(BaseModel):
    name: str
    mime: str
    data_b64: str


class AnalyzeIn(BaseModel):
    channel: str = "email"
    sender: str = ""
    subject: str = ""
    body: str = ""
    attachments: list[AttachmentIn] = []


class EmailListItem(BaseModel):
    id: str
    sender: str
    subject: str
    snippet: str
    received_at: datetime
    verdict: str | None = None
    risk_score: int | None = None
