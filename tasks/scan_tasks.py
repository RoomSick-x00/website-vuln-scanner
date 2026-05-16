from workers.processor import run_scan

SCAN_MODES = {
    "quick":  ["http_headers", "tls"],
    "full":   ["http_headers", "tls", "dns", "xss"],
}

def enqueue_scan(scan_id: int, target_url: str, scan_types: list):
    queued_tasks = []

    for task_type in scan_types:
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