from celery import Celery
from celery.signals import setup_logging as celery_setup_logging

from app.core.config import get_settings
from app.core.logging import setup_logging

settings = get_settings()
settings.validate_for_runtime()

celery_app = Celery(
    "secure_file_scanner",
    broker=settings.REDIS_URL,
    include=["app.workers.scan_tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,          # results live in PostgreSQL, not in Redis
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.SCAN_TIME_LIMIT_SECONDS,
    task_time_limit=settings.SCAN_TIME_LIMIT_SECONDS + 30,
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"socket_connect_timeout": 3, "socket_timeout": 5},
    # Fail fast (-> HTTP 503) instead of hanging when Redis is down.
    task_publish_retry_policy={"max_retries": 1, "interval_start": 0.1, "interval_max": 0.5},
)


@celery_setup_logging.connect
def _configure_logging(**_: object) -> None:
    setup_logging(settings.LOG_LEVEL)
