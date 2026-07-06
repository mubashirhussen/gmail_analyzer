from pydantic import BaseModel


class Indicator(BaseModel):
    category: str
    severity: str  # low|medium|high|critical
    detail: str


class ThreatVerdict(BaseModel):
    verdict: str  # safe|suspicious|phishing|fraud
    risk_score: int
    confidence: int
    attack_category: str | None = None
    summary: str
    indicators: list[Indicator] = []
    recommendations: list[str] = []
