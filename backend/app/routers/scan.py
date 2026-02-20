from fastapi import APIRouter
from uuid import uuid4
from datetime import datetime
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.core.enums import ScanStatus

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("/", response_model=ScanResponse)
def create_scan(scan: ScanCreate):
    scan_id = str(uuid4())

    return {
        "id": scan_id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": ScanStatus.QUEUED,
        "created_at": datetime.utcnow(),
        "started_at": None,
        "finished_at": None
    }



@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str):
    # fake data for now
    return {
        "id": scan_id,
        "target": "https://example.com",
        "scan_type": "web",
        "status": ScanStatus.RUNNING,
        "created_at": datetime.utcnow(),
        "started_at": datetime.utcnow(),
        "finished_at": None
    }
