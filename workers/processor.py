from workers.scanner_modules.tls import TLSScanner
from workers.scanner_modules.https_headers import HTTPHeadersScanner
from tasks.celery_app import app

# way to map a task_type string to the right scanner class.
SCANNER_REGISTRY = {
    "tls": TLSScanner(),
    "http_headers": HTTPHeadersScanner(),
}

@app.task(name="workers.processor.run_scan", bind=True, max_retries=3) #bind=True Makes self available inside the task — needed for self.retry(). Without it you can't retry on failure.
def run_scan(self, scan_id:int, task_type:str, target_url:str):
    scanner = SCANNER_REGISTRY.get(task_type)
    
    if scanner is None:
        return{
            "scan_id": scan_id,
            "task_type": task_type,
            "status": "failed",
            "error": f"No scanner registered for task_type: '{task_type}'",
            "findings": [],
        }
    try:
        raw_findings = scanner.safe_scan(target_url)
    except Exception as e:
        # Temporary failure — retry with exponential backoff
        # 1st retry after 10s, 2nd after 20s, 3rd after 40s
        try:
            raise self.retry(exc=e, countdown=10 * (2 ** self.request.retries))
        except self.MaxRetriesExceededError:
            return{
                "scan_id": scan_id,
                "task_type": task_type,
                "status": "failed",
                "error": f"Scanner failed after 3 retries: {str(e)}",
                "findings": [],
            }
    
    enriched_findings = [
        {**finding, "scan_id": sccan_id, "task_type": task_type}
        for finding in raw_findings
    ]
    
    return {
        "scan_id": scan_id,
        "task_type": task_type,
        "status": "completed",
        "findings": enriched_findings,
    }