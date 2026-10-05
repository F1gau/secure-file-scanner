import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.db.models import RiskLevel, ScanStatus, Severity


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: uuid.UUID


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    file_id: uuid.UUID
    status: ScanStatus
    risk_score: int | None
    risk_level: RiskLevel | None
    error_message: str | None  # short sanitized reason, never a traceback
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scanner: str
    rule: str
    severity: Severity
    description: str
    evidence: str | None  # masked / truncated; full secrets are never stored
    confidence: float
