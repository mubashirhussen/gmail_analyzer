from datetime import datetime
from pydantic import BaseModel


class ReportDoc(BaseModel):
    user_id: str
    period: str  # daily|weekly|monthly|adhoc
    fmt: str  # pdf|csv|xlsx
    generated_at: datetime
    storage_url: str | None = None
    summary: dict = {}
