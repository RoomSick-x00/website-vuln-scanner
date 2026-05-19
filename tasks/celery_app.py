import os
from celery import Celery

# REDIS_URL can be set via environment variable.
# Local development defaults to redis://localhost:6379/0
# Docker sets this via docker-compose.yml e.g. REDIS_URL=redis://redis:6380/0
broker_url = os.getenv("CELERY_BROKER_URL") or os.getenv("REDIS_URL", "redis://localhost:6379/0")
result_backend = os.getenv("CELERY_RESULT_BACKEND") or os.getenv("REDIS_URL") or broker_url

app = Celery(
    "website_vuln_scanner",
    broker=broker_url,
    backend=result_backend,
    include=["tasks.scan_tasks", "workers.processor"],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    result_expires=3600,
)

# To run locally:
# celery -A tasks.celery_app worker --loglevel=info
#
# To run with solo pool (Windows, no multiprocessing):
# celery -A tasks.celery_app:app worker --loglevel=info --pool=solo
