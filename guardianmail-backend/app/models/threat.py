from datetime import datetime
from pydantic import BaseModel


class ThreatDoc(BaseModel):
    user_id: str
    channel: str  # email|social
    sender: str = ""
    subject: str = ""
    verdict: str
    risk_score: int
    attack_category: str | None = None
    url_intel: dict | None = None
    email_auth: dict | None = None
    ocr: list[dict] | None = None
    created_at: datetime
