"""Celery application factory. Foundation only — business tasks register elsewhere."""
from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging

from app.core.config import settings
from app.core.logging import configure_logging
from app.workers.scheduler import BEAT_SCHEDULE


@setup_logging.connect
def _configure_celery_logging(**_kwargs):
    configure_logging()


celery = Celery(
    settings.APP_NAME.replace(" ", "_").lower(),
    broker=settings.celery_broker,
    backend=settings.celery_backend,
    include=[
        "app.workers.gmail_sync",
        "app.workers.ocr_tasks",
        "app.workers.phishing_tasks",
        "app.workers.report_tasks",
        "app.workers.webhook_tasks",
        "app.workers.complaint_tasks",
        "app.workers.threat_tasks",
        "app.workers.ai_tasks",
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
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=settings.CELERY_WORKER_PREFETCH_MULTIPLIER,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT_S,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT_S,
    broker_connection_retry_on_startup=True,
    result_expires=60 * 60 * 24,
    task_default_retry_delay=30,
    task_annotations={"*": {"max_retries": 3}},
)
