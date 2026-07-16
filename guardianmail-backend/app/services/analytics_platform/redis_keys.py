"""Redis key builders for the analytics platform.

Namespacing scheme
------------------
* `am:` prefix stands for "analytics module" — makes ops greps cheap.
* Every key embeds the user id so multi-tenant eviction is straightforward.
* Time-filter and scope are stable strings; keys are safe to enumerate and
  invalidate on write events (`invalidate_user`).
"""
from __future__ import annotations

PREFIX = "am"

DASHBOARD_TTL_S = 300              # 5 minutes for composed dashboards
CHART_TTL_S = 180
KPI_TTL_S = 120
REPORT_TTL_S = 60 * 15             # 15m for report status polls
SCORE_TTL_S = 300
RATE_LIMIT_TTL_S = 60


def dashboard_key(user_id: str, scope: str, time_filter: str) -> str:
    return f"{PREFIX}:dash:{user_id}:{scope}:{time_filter}"


def chart_key(user_id: str, chart: str, time_filter: str) -> str:
    return f"{PREFIX}:chart:{user_id}:{chart}:{time_filter}"


def kpi_key(user_id: str, kpi: str, time_filter: str) -> str:
    return f"{PREFIX}:kpi:{user_id}:{kpi}:{time_filter}"


def score_key(user_id: str, kind: str) -> str:
    return f"{PREFIX}:score:{user_id}:{kind}"


def report_key(report_id: str) -> str:
    return f"{PREFIX}:report:{report_id}"


def user_pattern(user_id: str) -> str:
    return f"{PREFIX}:*:{user_id}:*"


def rate_limit_key(user_id: str, bucket: str) -> str:
    return f"{PREFIX}:rl:{user_id}:{bucket}"
