from sqlalchemy import Column, String, DateTime, JSON, Boolean
from sqlalchemy.sql import func
from app.database import Base
from app.core.enums import ScanStatus


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    scan_mode = Column(String, nullable=False, default="quick")
    scan_type = Column(String, nullable=True)  # legacy alias; kept for existing rows
    status = Column(String, default=ScanStatus.QUEUED)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    findings = Column(JSON, nullable=True, default=list)
    verification_token = Column(String, nullable=True)
    verified = Column(Boolean, default=False)
