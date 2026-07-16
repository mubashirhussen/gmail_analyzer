"""Repository barrel — DI-friendly single import site."""
from app.repositories.analytics import AnalyticsRepository
from app.repositories.attachment_records import AttachmentRecordRepository
from app.repositories.audit_logs import AuditLogRepository
from app.repositories.background_jobs import BackgroundJobRepository
from app.repositories.base import BaseRepository
from app.repositories.complaints import ComplaintRepository
from app.repositories.devices import DeviceRepository
from app.repositories.emails import EmailRepository
from app.repositories.evidence_packs import EvidencePackRepository
from app.repositories.notifications import NotificationRepository
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.security_events import SecurityEventRepository
from app.repositories.sessions import SessionRepository
from app.repositories.threat_indicators import ThreatIndicatorRepository
from app.repositories.threats import ThreatReportRepository
from app.repositories.users import UserRepository

__all__ = [
    "BaseRepository",
    "UserRepository",
    "DeviceRepository",
    "SessionRepository",
    "RefreshTokenRepository",
    "AuditLogRepository",
    "EmailRepository",
    "ThreatReportRepository",
    "ThreatIndicatorRepository",
    "ComplaintRepository",
    "EvidencePackRepository",
    "NotificationRepository",
    "AnalyticsRepository",
    "SecurityEventRepository",
    "BackgroundJobRepository",
]
