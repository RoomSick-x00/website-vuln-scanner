from workers.processor import run_scan

SCAN_MODES = {
    "quick": ["tls", "http_headers", "dns"],
    "full": ["tls", "http_headers", "dns", "xss"],
}


def _resolve_scan_types(scan_mode: str, scan_types: list | None) -> list[str]:
    if scan_types:
        return scan_types
    if scan_mode in SCAN_MODES:
        return SCAN_MODES[scan_mode]
    if scan_mode and "," in scan_mode:
        return [s.strip() for s in scan_mode.split(",") if s.strip()]
    return SCAN_MODES["quick"]


def enqueue_scan(
    scan_id: str,
    target_url: str,
    scan_mode: str = "quick",
    scan_types: list | None = None,
):
    modules = _resolve_scan_types(scan_mode, scan_types)
    effective_mode = scan_mode if scan_mode in SCAN_MODES else "custom"
    queued_tasks = []

    for task_type in modules:
        task = run_scan.delay(
            scan_id=scan_id,
            task_type=task_type,
            target_url=target_url,
            scan_mode=effective_mode,
            allowed_modules=modules,
        )
        queued_tasks.append({
            "task_type": task_type,
            "celery_task_id": task.id,
            "status": "QUEUED",
        })

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_mode": effective_mode,
        "tasks": queued_tasks,
    }
