from celery import Celery

from app.core.config import settings
from app.workers.scheduler import BEAT_SCHEDULE

celery = Celery(
    "guardianmail",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.gmail_sync",
        "app.workers.ocr_tasks",
        "app.workers.phishing_tasks",
        "app.workers.report_tasks",
        "app.workers.webhook_tasks",
    ],
)
celery.conf.update(
    task_default_queue="default",
    task_routes={
        "gmail.*": {"queue": "default"},
        "ocr.*": {"queue": "ocr"},
        "threat.*": {"queue": "threat"},
        "reports.*": {"queue": "report"},
        "security.*": {"queue": "default"},
    },
    beat_schedule=BEAT_SCHEDULE,
    timezone="UTC",
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=240,
)
