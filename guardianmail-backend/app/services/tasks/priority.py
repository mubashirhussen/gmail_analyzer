"""Task priorities and queue routing.

Central source of truth for:

* The five priority buckets exposed to callers.
* Redis broker `x-max-priority` config (0=lowest, 9=highest).
* Queue-name constants — services should never hard-code queue strings.
"""
from __future__ import annotations

from enum import IntEnum


class TaskPriority(IntEnum):
    BACKGROUND = 1
    LOW = 3
    NORMAL = 5
    HIGH = 7
    CRITICAL = 9


# ---- queue names -----------------------------------------------------------
Q_DEFAULT = "default"
Q_GMAIL = "gmail"
Q_THREAT = "threat"
Q_AI = "ai"
Q_OCR = "ocr"
Q_ANALYTICS = "analytics"
Q_NOTIFICATIONS = "notifications"
Q_COMPLAINTS = "complaints"
Q_REPORTS = "report"
Q_MAINTENANCE = "maintenance"
Q_HIGH_PRIORITY = "high_priority"
Q_LOW_PRIORITY = "low_priority"
Q_DEAD_LETTER = "dead_letter"

ALL_QUEUES: tuple[str, ...] = (
    Q_DEFAULT, Q_GMAIL, Q_THREAT, Q_AI, Q_OCR, Q_ANALYTICS,
    Q_NOTIFICATIONS, Q_COMPLAINTS, Q_REPORTS, Q_MAINTENANCE,
    Q_HIGH_PRIORITY, Q_LOW_PRIORITY, Q_DEAD_LETTER,
)


# task-name prefix → queue mapping. Extends the existing celery_app routes
# rather than replacing them.
TASK_PREFIX_ROUTES: dict[str, str] = {
    "gmail.*": Q_GMAIL,
    "threat.*": Q_THREAT,
    "ai.*": Q_AI,
    "ocr.*": Q_OCR,
    "analytics.*": Q_ANALYTICS,
    "notifications.*": Q_NOTIFICATIONS,
    "complaints.*": Q_COMPLAINTS,
    "reports.*": Q_REPORTS,
    "maintenance.*": Q_MAINTENANCE,
    "security.*": Q_DEFAULT,
    "webhooks.*": Q_DEFAULT,
    "dead_letter.*": Q_DEAD_LETTER,
}


def queue_for(task_name: str) -> str:
    """Best-effort queue lookup used by dispatch when caller omits it."""
    prefix = task_name.split(".", 1)[0]
    return TASK_PREFIX_ROUTES.get(prefix + ".*", Q_DEFAULT)
