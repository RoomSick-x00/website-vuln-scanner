from fastapi import APIRouter, Depends, HTTPException
from uuid import uuid4
from datetime import datetime
from sqlalchemy.orm import Session

from app.schemas.scan import ScanCreate, ScanResponse
from app.core.enums import ScanStatus
from app.database import get_db
from app.models.scan import Scan
from tasks.scan_tasks import enqueue_scan, SCAN_MODES

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse)
def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    scan_id = str(uuid4())

    # Resolve scan_types from scan_type field
    if scan.scan_type in SCAN_MODES:
        scan_types = SCAN_MODES[scan.scan_type]
    elif scan.scan_type:
        # custom — comma separated e.g. "http_headers,xss"
        scan_types = [s.strip() for s in scan.scan_type.split(",")]
    else:
        scan_types = SCAN_MODES["quick"]

    new_scan = Scan(
        id=scan_id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=ScanStatus.QUEUED
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    enqueue_scan(scan_id, scan.target, scan_types)

    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(Scan).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.patch("/{scan_id}/status")
def update_status(scan_id: str, status: ScanStatus, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.status = status
    if status == ScanStatus.RUNNING:
        scan.started_at = datetime.utcnow()
    if status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
        scan.finished_at = datetime.utcnow()

    db.commit()
    db.refresh(scan)
    return scan