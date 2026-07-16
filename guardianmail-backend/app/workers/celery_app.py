"""Celery application factory.

The factory intentionally stays thin. Business tasks self-register by being
imported through the `include` list. Module 8 extends this file with:

* additional worker modules (notifications / analytics / maintenance / hooks),
* the full production queue set with a broker `x-max-priority` of 9,
* signal wiring via `app.workers.hooks` (imported for side-effects).
"""
from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging
from kombu import Queue

from app.core.config import settings
from app.core.logging import configure_logging
from app.services.tasks.priority import (
    ALL_QUEUES, Q_AI, Q_ANALYTICS, Q_COMPLAINTS, Q_DEAD_LETTER, Q_DEFAULT,
    Q_GMAIL, Q_HIGH_PRIORITY, Q_LOW_PRIORITY, Q_MAINTENANCE,
    Q_NOTIFICATIONS, Q_OCR, Q_REPORTS, Q_THREAT,
)
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
        # ---- Module 8: platform tasks ----
        "app.workers.notification_tasks",
        "app.workers.analytics_tasks",
        "app.workers.maintenance_tasks",
        # ---- Module 9: complaint & evidence platform ----
        "app.workers.complaint_platform_tasks",
    ],
)

# Broker-side priority requires each queue to advertise x-max-priority.
_QUEUE_ARGS = {"x-max-priority": 9}
task_queues = tuple(
    Queue(name, routing_key=name, queue_arguments=_QUEUE_ARGS) for name in ALL_QUEUES
)

celery.conf.update(
    task_default_queue=Q_DEFAULT,
    task_queues=task_queues,
    task_routes={
        # existing modules (unchanged)
        "gmail.*": {"queue": Q_GMAIL},
        "ocr.*": {"queue": Q_OCR},
        "threat.*": {"queue": Q_THREAT},
        "reports.*": {"queue": Q_REPORTS},
        "security.*": {"queue": Q_DEFAULT},
        "ai.*": {"queue": Q_AI},
        # Module 8 additions
        "analytics.*": {"queue": Q_ANALYTICS},
        "notifications.*": {"queue": Q_NOTIFICATIONS},
        "complaints.*": {"queue": Q_COMPLAINTS},
        "maintenance.*": {"queue": Q_MAINTENANCE},
        "dead_letter.*": {"queue": Q_DEAD_LETTER},
        "priority.high.*": {"queue": Q_HIGH_PRIORITY},
        "priority.low.*": {"queue": Q_LOW_PRIORITY},
    },
    beat_schedule=BEAT_SCHEDULE,
    timezone="UTC",
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=settings.CELERY_WORKER_PREFETCH_MULTIPLIER,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT_S,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT_S,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 3600},
    result_expires=60 * 60 * 24,
    task_default_retry_delay=30,
    task_annotations={"*": {"max_retries": 3}},
)

# Import for side effects — registers task_prerun / postrun / retry / failure
# handlers that persist execution history and emit Prometheus counters.
from app.workers import hooks  # noqa: E402,F401
