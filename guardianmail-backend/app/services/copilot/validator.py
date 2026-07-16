"""Response Validator — enforces GuardianMail evidence-only invariants.

Given the model's JSON string and the built context, the validator:
* parses JSON (with a lenient recovery pass),
* normalizes required fields,
* verifies every `evidence[].value` appears somewhere in the context,
* down-scores confidence when unsupported claims are detected,
* returns a structured `ValidationReport` for the API + audit log.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.services.copilot.context_service import BuiltContext
from app.services.copilot.prompt_builder import build_context_payload


REQUIRED_FIELDS = (
    "summary", "evidence", "threat_indicators", "ai_reasoning",
    "confidence", "recommended_action", "educational_tip", "related_concepts",
)


@dataclass
class ValidationReport:
    ok: bool
    issues: list[str] = field(default_factory=list)
    unsupported_evidence: list[dict[str, Any]] = field(default_factory=list)
    supported_count: int = 0
    total_evidence: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "issues": self.issues,
            "unsupported_evidence": self.unsupported_evidence,
            "supported_count": self.supported_count,
            "total_evidence": self.total_evidence,
        }


def _extract_json(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return {}
    return {}


def _flatten(obj: Any) -> list[str]:
    out: list[str] = []
    if obj is None:
        return out
    if isinstance(obj, (str, int, float, bool)):
        out.append(str(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_flatten(v))
    return out


class ResponseValidator:
    def validate(self, raw_text: str, ctx: BuiltContext) -> tuple[dict[str, Any], ValidationReport]:
        report = ValidationReport(ok=True)
        obj = _extract_json(raw_text)
        if not obj:
            report.ok = False
            report.issues.append("non_json_response")
            obj = {}

        # Fill required fields with safe defaults.
        for k in REQUIRED_FIELDS:
            if k not in obj:
                report.issues.append(f"missing_field:{k}")
                obj[k] = [] if k in ("evidence", "threat_indicators",
                                     "related_concepts") else (
                    0.0 if k == "confidence" else ""
                )

        if not isinstance(obj.get("evidence"), list):
            obj["evidence"] = []
            report.issues.append("evidence_not_list")
        if not isinstance(obj.get("threat_indicators"), list):
            obj["threat_indicators"] = []
        if not isinstance(obj.get("related_concepts"), list):
            obj["related_concepts"] = []

        try:
            obj["confidence"] = max(0.0, min(1.0, float(obj.get("confidence") or 0.0)))
        except Exception:
            obj["confidence"] = 0.0
            report.issues.append("confidence_not_numeric")

        # Ground evidence against the context.
        ctx_haystack = set(
            s.strip().lower()
            for s in _flatten(build_context_payload(ctx))
            if s and len(s.strip()) > 1
        )
        supported = 0
        unsupported: list[dict[str, Any]] = []
        for e in obj["evidence"]:
            if not isinstance(e, dict):
                report.issues.append("evidence_item_not_object")
                continue
            val = e.get("value")
            needle = str(val).strip().lower() if val is not None else ""
            if needle and any(needle in h or h in needle for h in ctx_haystack):
                supported += 1
            else:
                unsupported.append(e)

        report.supported_count = supported
        report.total_evidence = len(obj["evidence"])
        report.unsupported_evidence = unsupported

        if not ctx.has_anchor:
            report.ok = False
            report.issues.append("no_evidence_anchor")

        if unsupported and report.total_evidence:
            ratio = 1 - (len(unsupported) / max(1, report.total_evidence))
            obj["confidence"] = round(obj["confidence"] * max(0.3, ratio), 3)
            report.issues.append(
                f"unsupported_evidence:{len(unsupported)}/{report.total_evidence}"
            )
            if len(unsupported) == report.total_evidence:
                report.ok = False

        return obj, report


response_validator = ResponseValidator()
