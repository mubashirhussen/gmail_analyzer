"""Central Celery Beat schedule.

Kept in a separate module so ops can tune cadence without touching the app
factory. Imported by `celery_app.py`. Module 8 extends the schedule with
platform-maintenance cadences (queue-depth snapshot, DLQ sizing).
"""
from celery.schedules import crontab

BEAT_SCHEDULE = {
    # ---- feature cadences (existing) --------------------------------
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
    # ---- Module 8 — platform maintenance ---------------------------
    "queue-depth-snapshot": {
        "task": "maintenance.snapshot_queue_depth",
        "schedule": crontab(minute="*"),
    },
    "dead-letter-size": {
        "task": "maintenance.dlq_size",
        "schedule": crontab(minute="*/5"),
    },
    "cleanup-background-jobs": {
        "task": "maintenance.cleanup_background_jobs",
        "schedule": crontab(hour=3, minute=15),
    },
    "analytics-daily-rollup": {
        "task": "analytics.daily_rollup",
        "schedule": crontab(hour=2, minute=0),
    },
    # Module 9 — complaint reminder sweeper.
    "complaint-platform-reminders": {
        "task": "complaints_platform.sweep_reminders",
        "schedule": crontab(minute="*/5"),
    },
}
