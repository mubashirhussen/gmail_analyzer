"""Central Celery Beat schedule.

Kept in a separate module so ops can tune cadence without touching the app
factory. Imported by `celery_app.py`.
"""
from celery.schedules import crontab

BEAT_SCHEDULE = {
    "gmail-sync-all": {
        "task": "gmail.sync_all",
        "schedule": crontab(minute="*/15"),
    },
    "nightly-analytics": {
        "task": "reports.nightly_rollup",
        "schedule": crontab(hour=1, minute=30),
    },
    "weekly-report": {
        "task": "reports.weekly_digest",
        "schedule": crontab(day_of_week="mon", hour=6, minute=0),
    },
    "cleanup-sessions": {
        "task": "security.cleanup_sessions",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "complaint-reminders": {
        "task": "complaints.sweep_reminders",
        "schedule": crontab(minute="*/5"),
    },
}
