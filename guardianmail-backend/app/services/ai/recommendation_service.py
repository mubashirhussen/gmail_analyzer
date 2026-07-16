"""Post-processes raw AI recommendations into a prioritized, deduplicated
`Recommendation` list.

Rules
-----
* Immediate actions always outrank long-term recommendations.
* Verdicts of critical severity force at minimum: "do not click",
  "do not reply", "report to security".
* Duplicates (case-insensitive) are collapsed.
"""
from __future__ import annotations

from app.models.ai_report import Recommendation

_CRITICAL_MIN: tuple[tuple[str, str, str], ...] = (
    ("Do not click any links in this email.", "critical", "immediate"),
    ("Do not reply or share credentials.", "critical", "immediate"),
    ("Report the email to your organisation's security team.", "high", "immediate"),
)

_PRIORITY_FOR_RISK = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "low",
}


class RecommendationService:
    def build(
        self,
        *,
        risk_level: str,
        immediate: list[str],
        long_term: list[str],
        educational: list[str],
        technical: list[str],
    ) -> list[Recommendation]:
        priority = _PRIORITY_FOR_RISK.get(risk_level, "medium")
        recs: list[Recommendation] = []
        seen: set[str] = set()

        def _add(text: str, prio: str, cat: str) -> None:
            key = text.strip().lower()
            if not key or key in seen:
                return
            seen.add(key)
            recs.append(Recommendation(
                action=text.strip(), priority=prio, category=cat,
                rationale="", 
            ))

        if risk_level in {"high", "critical"}:
            for text, prio, cat in _CRITICAL_MIN:
                _add(text, prio, cat)

        for text in immediate:
            _add(text, priority, "immediate")
        for text in long_term:
            _add(text, "medium", "long_term")
        for text in educational:
            _add(text, "low", "educational")
        for text in technical:
            _add(text, "low", "technical")

        return recs
