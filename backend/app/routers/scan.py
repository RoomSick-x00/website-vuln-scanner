from fastapi import APIRouter
from uuid import uuid4
from datetime import datetime
from app.schemas.scan import ScanCreate, ScanResponse
from app.core.enums import ScanStatus
# enqueue_scan(scan_id=scan_id, target_url=scan.target)
from fastapi import Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import Scan
from tasks.scan_tasks import enqueue_scan

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
    print("CREATE_SCAN HIT")
    enqueue_scan(scan_id, scan.target)
    

    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).all()
    return scans

from fastapi import HTTPException

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