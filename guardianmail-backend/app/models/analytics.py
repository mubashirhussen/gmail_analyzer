from datetime import datetime
from pydantic import BaseModel


class AnalyticsSnapshot(BaseModel):
    user_id: str
    at: datetime
    threat_score: int      # 0-100 (higher = more incoming threats)
    security_score: int    # 0-100 (higher = better hygiene)
    privacy_score: int     # 0-100
    trust_score: int       # 0-100
    counts: dict = {}      # {safe, suspicious, phishing, fraud}
    top_categories: list[dict] = []  # [{category, count}]
