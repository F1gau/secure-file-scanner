import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.schemas.scan import ScanOut


class AdminScanOut(ScanOut):
    owner_id: uuid.UUID


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID | None
    action: str
    ip_address: str | None
    request_id: str | None
    details: dict[str, Any] | None
    created_at: datetime


class StatsOut(BaseModel):
    total_files: int
    total_scans: int
    high_risk_scans: int  # scans with risk level HIGH (CRITICAL is counted separately)
    critical_scans: int
    failed_scans: int
    average_scan_time_seconds: float | None  # over the most recent finished scans
