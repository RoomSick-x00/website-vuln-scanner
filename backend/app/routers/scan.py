from fastapi import APIRouter, Depends, HTTPException
from uuid import uuid4
from datetime import datetime
from sqlalchemy.orm import Session
import dns.resolver

from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanDetailResponse,
    VerificationTokenResponse,
    VerifyDomainResponse,
)
from app.core.enums import ScanStatus
from app.database import get_db
from app.models.scan import Scan
from app.scan_utils import (
    extract_domain,
    generate_verification_token,
    group_findings,
    module_lists,
    resolve_scan_modules,
)
from tasks.scan_tasks import enqueue_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


def _effective_scan_mode(payload: ScanCreate) -> str:
    if payload.scan_mode is not None:
        return payload.scan_mode
    if payload.scan_type:
        return payload.scan_type
    return "quick"


def _modules_for_scan(scan: Scan) -> tuple[list[str], list[str]]:
    if scan.scan_mode == "custom" and scan.scan_type and "," in scan.scan_type:
        selected = [m.strip() for m in scan.scan_type.split(",")]
        return module_lists("custom", selected)
    return module_lists(scan.scan_mode)


def _build_scan_detail(scan: Scan) -> ScanDetailResponse:
    findings = scan.findings or []
    ran_modules, skipped_modules = _modules_for_scan(scan)
    return ScanDetailResponse(
        scan_id=scan.id,
        target=scan.target,
        status=scan.status,
        scan_mode=scan.scan_mode,
        ran_modules=ran_modules,
        skipped_modules=skipped_modules,
        results=findings,
        grouped=group_findings(findings),
        completed_modules=list(scan.completed_modules or []),
        verified=bool(scan.verified),
    )


@router.post("/", response_model=ScanResponse)
def create_scan(scan: ScanCreate, db: Session = Depends(get_db)):
    scan_id = str(uuid4())
    raw_mode = _effective_scan_mode(scan)
    scan_modules = resolve_scan_modules(raw_mode, scan.modules)
    if not scan_modules:
        raise HTTPException(status_code=422, detail="Select at least one valid scanner module.")
    domain = extract_domain(scan.target)

    if scan.modules:
        stored_mode = "custom"
    elif raw_mode in ("quick", "full"):
        stored_mode = raw_mode
    elif "," in raw_mode:
        stored_mode = "custom"
    else:
        stored_mode = raw_mode

    needs_verification = "xss" in scan_modules
    verification_token = (
        generate_verification_token(domain) if needs_verification else None
    )

    new_scan = Scan(
        id=scan_id,
        target=scan.target,
        scan_mode=stored_mode,
        scan_type=raw_mode,
        status=ScanStatus.QUEUED,
        completed_modules=[],
        verification_token=verification_token,
        verified=not needs_verification,
    )

    if stored_mode == "custom":
        new_scan.scan_type = ",".join(scan_modules)

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    enqueue_scan(scan_id, scan.target, stored_mode, scan_modules)

    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(Scan).all()


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _build_scan_detail(scan)


@router.get("/{scan_id}/verification-token", response_model=VerificationTokenResponse)
def get_verification_token(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    domain = extract_domain(scan.target)
    token = scan.verification_token or generate_verification_token(domain)
    if not scan.verification_token:
        scan.verification_token = token
        db.commit()

    return VerificationTokenResponse(
        scan_id=scan.id,
        domain=domain,
        verification_token=token,
        txt_host=f"_vuln-verify.{domain}",
        txt_value=token,
    )


@router.post("/{scan_id}/verify", response_model=VerifyDomainResponse)
def verify_scan_domain(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    domain = extract_domain(scan.target)
    token = scan.verification_token or generate_verification_token(domain)
    txt_host = f"_vuln-verify.{domain}"

    try:
        answers = dns.resolver.resolve(txt_host, "TXT")
        for record in answers:
            for chunk in record.strings:
                value = chunk.decode(errors="ignore") if isinstance(chunk, bytes) else str(chunk)
                if token in value:
                    scan.verified = True
                    scan.verification_token = token
                    db.commit()
                    return VerifyDomainResponse(
                        verified=True,
                        message="Domain verified successfully.",
                    )
    except Exception:
        pass

    return VerifyDomainResponse(
        verified=False,
        message=(
            f"TXT record not found at {txt_host}. "
            f"Add a TXT record with value '{token}' and try again."
        ),
    )


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
