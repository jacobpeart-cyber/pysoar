"""Celery application configuration"""

from celery import Celery

from src.core.config import settings

# Create Celery app
celery_app = Celery(
    "pysoar",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "src.workers.tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,  # Results expire after 1 day
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "cleanup-old-executions": {
        "task": "src.workers.tasks.cleanup_old_executions",
        "schedule": 3600.0,  # Every hour
    },
    "refresh-ioc-enrichments": {
        "task": "src.workers.tasks.refresh_ioc_enrichments",
        "schedule": 86400.0,  # Every 24 hours
    },
    "check-scheduled-playbooks": {
        "task": "src.workers.tasks.check_scheduled_playbooks",
        "schedule": 60.0,  # Every minute
    },
}
