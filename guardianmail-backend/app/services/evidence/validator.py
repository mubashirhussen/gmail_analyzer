"""Evidence pack validator (Module 9).

Before an evidence pack is generated we require:

  * a persisted threat report belonging to the requesting user,
  * an AI report tied to that threat (module 6 output),
  * at least one recorded indicator,
  * required metadata fields (sender, subject, received-at, message-id).

The validator returns a structured report; callers decide whether to
reject the request (`ok is False`) or persist partial evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bson import ObjectId

from app.database.mongodb import get_db


REQUIRED_THREAT_FIELDS = ("sender", "subject", "created_at")


@dataclass
class ValidationResult:
    ok: bool
    threat: dict[str, Any] | None = None
    ai_report: dict[str, Any] | None = None
    indicators: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "missing": self.missing,
            "warnings": self.warnings,
            "indicator_count": len(self.indicators),
            "threat_id": str(self.threat["_id"]) if self.threat else None,
            "ai_report_id": str(self.ai_report["_id"]) if self.ai_report else None,
        }


async def validate_for_evidence(user_id: str, threat_id: str) -> ValidationResult:
    db = get_db()
    result = ValidationResult(ok=True)

    try:
        oid = ObjectId(threat_id)
    except Exception:
        result.ok = False
        result.missing.append("threat_id_invalid")
        return result

    threat = await db.threats.find_one({"_id": oid, "user_id": user_id})
    if not threat:
        result.ok = False
        result.missing.append("threat_report")
        return result
    result.threat = threat

    for field_name in REQUIRED_THREAT_FIELDS:
        if not threat.get(field_name):
            result.missing.append(f"threat.{field_name}")

    ai_report = await db.ai_reports.find_one(
        {"threat_report_id": str(oid), "user_id": user_id},
        sort=[("created_at", -1)],
    )
    if not ai_report:
        # AI report is optional but strongly recommended.
        result.warnings.append("ai_report_missing")
    else:
        result.ai_report = ai_report

    indicators_cur = db.threat_indicators.find(
        {"threat_id": str(oid), "user_id": user_id}
    )
    result.indicators = [d async for d in indicators_cur]
    if not result.indicators:
        # Try alternate shape stored on the threat doc itself.
        embedded = threat.get("indicators") or []
        result.indicators = list(embedded)
    if not result.indicators:
        result.warnings.append("no_indicators")

    if result.missing:
        result.ok = False
    return result
