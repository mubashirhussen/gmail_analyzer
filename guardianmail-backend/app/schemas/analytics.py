from pydantic import BaseModel


class TrendPoint(BaseModel):
    date: str
    safe: int = 0
    suspicious: int = 0
    phishing: int = 0
    fraud: int = 0


class DashboardOut(BaseModel):
    scanned: int
    threats: int
    devices: int
    protection_score: int
