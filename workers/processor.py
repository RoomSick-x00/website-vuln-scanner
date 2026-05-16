from workers.scanner_modules.tls import TLSScanner
from workers.scanner_modules.https_headers import HTTPHeadersScanner
from workers.scanner_modules.xss import XSSScanner
from workers.scanner_modules.dns import DNSScanner
from tasks.celery_app import app
from datetime import datetime, timezone
from app.database import SessionLocal
from app.models.scan import Scan
from app.core.enums import ScanStatus

SCANNER_REGISTRY = {
    "tls": TLSScanner(),
    "http_headers": HTTPHeadersScanner(),
    "xss": XSSScanner(),
    "dns": DNSScanner(),
}

SCAN_MODES = {
    "quick": ["tls", "http_headers", "dns"],
    "full":  ["tls", "http_headers", "dns", "xss"],
}

@app.task(name="workers.processor.run_scan", bind=True, max_retries=3)
def run_scan(self, scan_id: int, task_type: str, target_url: str, scan_mode: str = "quick"):
    # Skip this scanner if not allowed in the current scan mode
    allowed_scanners = SCAN_MODES.get(scan_mode, SCAN_MODES["quick"])
    if task_type not in allowed_scanners:
        return {
            "scan_id": scan_id,
            "task_type": task_type,
            "status": "skipped",
            "findings": [],
        }
        
    started_at = datetime.now(timezone.utc).isoformat()

    scanner = SCANNER_REGISTRY.get(task_type)

    if scanner is None:
        return {
            "scan_id": scan_id,
            "task_type": task_type,
            "status": "failed",
            "error": f"No scanner registered for task_type: {task_type}",
            "findings": [],
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }

    try:
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

        raw_findings = scanner.safe_scan(target_url, timeout=30)

    except Exception as e:
        try:
            raise self.retry(exc=e, countdown=10 * (2 ** self.request.retries))
        except self.MaxRetriesExceededError:
            return {
                "scan_id": scan_id,
                "task_type": task_type,
                "status": "failed",
                "error": f"Scanner failed after 3 retries: {str(e)}",
                "findings": [],
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }

    enriched_findings = [
        {**finding, "scan_id": scan_id, "task_type": task_type}
        for finding in raw_findings
    ]

    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if scan:
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = datetime.now(timezone.utc)
        scan.findings = enriched_findings
        db.commit()

    db.close()

    return {
        "scan_id": scan_id,
        "task_type": task_type,
        "status": "completed",
        "findings": enriched_findings,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }