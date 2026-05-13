from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.core.enums import ScanStatus

class ScanCreate(BaseModel):
    target: str
    scan_type: str

class ScanResponse(BaseModel):
    id: str
    target: str
    scan_type: str
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
