from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery = Celery(
    "guardianmail",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.gmail_sync",
        "app.workers.ocr_tasks",
        "app.workers.phishing_tasks",
        "app.workers.report_tasks",
    ],
)
celery.conf.update(
    task_default_queue="default",
    task_routes={
        "gmail.*": {"queue": "default"},
        "ocr.*": {"queue": "ocr"},
        "threat.*": {"queue": "threat"},
        "reports.*": {"queue": "report"},
    },
    beat_schedule={
        "gmail-sync-all": {"task": "gmail.sync_all", "schedule": crontab(minute="*/15")},
        "nightly-analytics": {"task": "reports.nightly_rollup", "schedule": crontab(hour=1, minute=30)},
    },
    timezone="UTC",
)
