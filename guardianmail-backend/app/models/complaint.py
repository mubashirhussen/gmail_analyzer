"""Complaint document — auto-drafted CERT-In/cybercrime.gov.in submissions.

Owned by the complaint service (module 9). Defined here as part of the
persistence schema; repositories only expose data access.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.models.base import Document

ComplaintStatus = Literal[
    "drafted", "scheduled", "queued", "sent", "downloaded", "acknowledged", "failed"
]
ComplaintDestination = Literal["cybercrime_gov_in", "report_phishing_gov_in", "cert_in"]
ComplaintType = Literal["phishing", "bec", "fraud", "malware", "impersonation", "other"]


class Complaint(Document):
    user_id: str
    threat_report_id: str
    email_id: str | None = None
    evidence_pack_id: str | None = None

    complaint_type: ComplaintType = "phishing"
    destination: ComplaintDestination = "cybercrime_gov_in"
    template_id: str | None = None

    subject: str
    draft_body: str
    draft_hash: str  # sha256 of draft_body — detects tampering
    attachments: list[str] = Field(default_factory=list)  # evidence file refs

    status: ComplaintStatus = "drafted"
    scheduled_for: datetime | None = None
    reminded_at: datetime | None = None
    submitted_at: datetime | None = None
    acknowledged_at: datetime | None = None
    external_reference: str | None = None
    failure_reason: str | None = None
    retry_count: int = 0
