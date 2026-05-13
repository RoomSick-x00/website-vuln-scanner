from workers.processor import run_scan

SUPPORTED_SCAN_TYPES = ["http_headers", "tls"]


def enqueue_scan(scan_id: int, target_url: str):
    queued_tasks = []

    for task_type in SUPPORTED_SCAN_TYPES:
        task = run_scan.delay(
            scan_id=scan_id,
            task_type=task_type,
            target_url=target_url
        )

        queued_tasks.append({
            "task_type": task_type,
            "celery_task_id": task.id,
            "status": "QUEUED"
        })

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "tasks": queued_tasks
    }