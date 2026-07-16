"""Facade — the single entry point other modules use to feed the SOC.

Keeps SOC's cross-cutting integration surface small: every subsystem can
call `soc_service.ingest_detection(...)` (or `.ingest_threat(...)`) and
never has to know about incident/alert/audit plumbing.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.soc.alert_service import alert_service
from app.services.soc.audit_service import audit_service
from app.services.soc.incident_service import incident_service

_log = get_logger(__name__)


class SOCService:
    """Coordinator between platform events and SOC persistence."""

    async def ingest_detection(self, detection: dict[str, Any]) -> str | None:
        """Promote a Phase 17 detection result into a SOC incident.

        Best-effort and non-invasive: any failure is logged and swallowed so
        the calling detection pipeline is never blocked.
        """
        try:
            risk = float(detection.get("risk_score", 0) or 0)
            if risk < 40:
                return None  # only medium+ becomes an incident
            incident = await incident_service.create(
                user_id=detection.get("user_id", "unknown"),
                source="detection",
                source_ref=str(detection.get("_id") or detection.get("id") or ""),
                incident_type="phishing" if "phish" in (detection.get("classification") or "") else "phishing",
                threat_category=(detection.get("categories") or [None])[0],
                confidence=float(detection.get("confidence", 0.5) or 0.5),
                risk_score=risk,
                subject=detection.get("subject"),
                sender=detection.get("sender"),
                urls=[u.get("url") for u in detection.get("urls", []) if isinstance(u, dict) and u.get("url")],
                attachments=detection.get("attachments") or [],
                evidence=[{"kind": "detection", "ref": detection.get("_id")}],
            )
            if risk >= 85:
                await alert_service.raise_alert(
                    kind="critical_threat",
                    severity="critical",
                    title="Critical threat detected",
                    message=f"risk_score={risk:.1f} sender={detection.get('sender')}",
                    incident_id=incident.get("_id"),
                    user_id=detection.get("user_id"),
                    meta={"detection_id": detection.get("_id")},
                )
            return incident.get("_id")
        except Exception as exc:  # pragma: no cover
            _log.warning("soc_ingest_detection_failed", err=str(exc))
            return None

    async def ingest_threat(self, threat: dict[str, Any]) -> str | None:
        try:
            score = float(threat.get("risk_score", 0) or 0)
            if score < 40:
                return None
            inc = await incident_service.create(
                user_id=threat.get("user_id", "unknown"),
                source="threat",
                source_ref=str(threat.get("_id") or ""),
                risk_score=score,
                confidence=float(threat.get("confidence", 0.5) or 0.5),
                sender=threat.get("sender"),
                subject=threat.get("subject"),
                domain=threat.get("domain"),
            )
            return inc.get("_id")
        except Exception as exc:  # pragma: no cover
            _log.warning("soc_ingest_threat_failed", err=str(exc))
            return None

    # audit passthrough for callers that only need one import
    audit = audit_service


soc_service = SOCService()
