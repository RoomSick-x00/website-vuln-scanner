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


def _expected_modules(scan_mode: str, allowed_modules: list | None) -> list:
    modules = allowed_modules or SCAN_MODES.get(scan_mode, SCAN_MODES["quick"])
    return [module for module in modules if module in SCANNER_REGISTRY]


def _mark_scan_failed(scan_id: str, error: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.now(timezone.utc)
            existing = list(scan.findings or [])
            scan.findings = existing + [{
                "module_name": "system",
                "task_type": "system",
                "scan_id": scan_id,
                "issue": "Scan task failed",
                "evidence": error,
                "severity": "medium",
                "score_penalty": 0,
                "remediation": "Review worker logs and retry the scan.",
            }]
            db.commit()
    finally:
        db.close()

@app.task(name="workers.processor.run_scan", bind=True, max_retries=3)
def run_scan(
    self,
    scan_id: int,
    task_type: str,
    target_url: str,
    scan_mode: str = "quick",
    allowed_modules: list | None = None,
):
    allowed_scanners = _expected_modules(scan_mode, allowed_modules)
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

    db = SessionLocal()
    should_close = True
    try:
        with db.begin():
            scan = db.query(Scan).filter(Scan.id == scan_id).with_for_update().first()
            if scan:
                scan.status = ScanStatus.RUNNING
                if not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
        raw_findings = scanner.safe_scan(target_url, timeout=30)

    except Exception as e:
        db.rollback()
        db.close()
        should_close = False
        try:
            raise self.retry(exc=e, countdown=10 * (2 ** self.request.retries))
        except self.MaxRetriesExceededError:
            _mark_scan_failed(scan_id, f"Scanner failed after 3 retries: {str(e)}")
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

    try:
        with db.begin():
            scan = db.query(Scan).filter(Scan.id == scan_id).with_for_update().first()
            if scan:
                existing = list(scan.findings or [])
                completed = list(scan.completed_modules or [])
                scan.findings = existing + enriched_findings
                if task_type not in completed:
                    completed.append(task_type)
                scan.completed_modules = completed

                expected = set(_expected_modules(scan_mode, allowed_modules))
                if expected and expected.issubset(set(completed)):
                    scan.status = ScanStatus.COMPLETED
                    scan.finished_at = datetime.now(timezone.utc)
                else:
                    scan.status = ScanStatus.RUNNING
    except Exception as e:
        db.rollback()
        db.close()
        should_close = False
        _mark_scan_failed(scan_id, f"Could not persist scan findings: {str(e)}")
        raise
    finally:
        if should_close:
            db.close()

    return {
        "scan_id": scan_id,
        "task_type": task_type,
        "status": "completed",
        "findings": enriched_findings,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
