from celery import Celery

app = Celery(
    "website_vuln_scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
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

# celery -A tasks.celery_app:app worker --loglevel=info --pool=solo   
#