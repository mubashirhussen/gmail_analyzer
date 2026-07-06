from datetime import datetime
from pydantic import BaseModel


class AuditLogDoc(BaseModel):
    user_id: str | None = None
    at: datetime
    event: str  # login|logout|threat_scan|device_change|error|report_export|...
    severity: str = "info"  # info|warn|error|critical
    ip: str | None = None
    user_agent: str | None = None
    meta: dict = {}
