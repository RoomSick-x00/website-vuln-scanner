from sqlalchemy import Column, String, DateTime
from sqlalchemy.sql import func
from app.database import Base
from app.core.enums import ScanStatus

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    status = Column(String, default=ScanStatus.QUEUED)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
