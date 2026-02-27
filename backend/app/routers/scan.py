from fastapi import APIRouter
from uuid import uuid4
from datetime import datetime
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.core.enums import ScanStatus

from fastapi import Depends
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.scan import Scan

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("/", response_model=ScanResponse)
def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):

    scan_id = str(uuid4())

    new_scan = Scan(
        id=scan_id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=ScanStatus.QUEUED
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return new_scan



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
