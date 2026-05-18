from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from app.core.enums import ScanStatus


class ScanCreate(BaseModel):
    target: str
    scan_mode: Optional[str] = None
    modules: Optional[List[str]] = None
    # Legacy field from older clients
    scan_type: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    target: str
    scan_mode: str = "quick"
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    findings: Optional[List[dict]] = Field(default_factory=list)
    completed_modules: Optional[List[str]] = Field(default_factory=list)
    verified: bool = False

    class Config:
        from_attributes = True


class ScanDetailResponse(BaseModel):
    scan_id: str
    target: str
    status: ScanStatus
    scan_mode: str
    ran_modules: List[str]
    skipped_modules: List[str]
    results: List[dict]
    grouped: dict[str, List[dict]]
    completed_modules: List[str] = Field(default_factory=list)
    verified: bool = False


class VerificationTokenResponse(BaseModel):
    scan_id: str
    domain: str
    verification_token: str
    txt_host: str
    txt_value: str


class VerifyDomainResponse(BaseModel):
    verified: bool
    message: str
