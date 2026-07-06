"""User-defined automation rules.

A rule is a small JSON: match ANY/ALL of conditions on a threat doc, then
perform actions (notify, tag, auto-report, quarantine). Kept declarative so
users can compose them from the UI without shipping code.
"""
from __future__ import annotations

from typing import Any, Iterable

from app.database.mongodb import get_db
from app.services.notifications.sender import notify

Condition = dict[str, Any]  # {"field": "verdict", "op": "eq", "value": "phishing"}
Action = dict[str, Any]     # {"type": "notify", "title": "..."}


def _get(doc: dict, path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _eval(cond: Condition, doc: dict) -> bool:
    v = _get(doc, cond["field"])
    op, target = cond.get("op", "eq"), cond.get("value")
    if op == "eq": return v == target
    if op == "ne": return v != target
    if op == "gt": return isinstance(v, (int, float)) and v > target
    if op == "gte": return isinstance(v, (int, float)) and v >= target
    if op == "lt": return isinstance(v, (int, float)) and v < target
    if op == "in": return v in (target or [])
    if op == "contains": return isinstance(v, str) and str(target) in v
    return False


def matches(rule: dict, doc: dict) -> bool:
    conds: Iterable[Condition] = rule.get("conditions", [])
    mode = rule.get("match", "all")
    results = [_eval(c, doc) for c in conds]
    return all(results) if mode == "all" else any(results)


async def apply_rules(user_id: str, threat: dict) -> list[str]:
    """Run all rules for a user against a freshly-scored threat; return action log."""
    db = get_db()
    ran: list[str] = []
    async for rule in db.automation_rules.find({"user_id": user_id, "enabled": True}):
        if not matches(rule, threat):
            continue
        for a in rule.get("actions", []):
            t = a.get("type")
            if t == "notify":
                await notify(user_id, title=a.get("title", "Rule matched"),
                             body=a.get("body", ""), severity=a.get("severity", "warn"),
                             meta={"rule_id": str(rule["_id"])})
            elif t == "tag":
                await db.threats.update_one({"_id": threat["_id"]},
                                            {"$addToSet": {"tags": a.get("tag", "flagged")}})
            elif t == "quarantine":
                await db.threats.update_one({"_id": threat["_id"]},
                                            {"$set": {"quarantined": True}})
            ran.append(f"{rule.get('name','rule')}:{t}")
    return ran
