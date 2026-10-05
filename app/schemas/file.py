import uuid
from datetime import datetime

from pydantic import BaseModel, field_serializer

from app.db.models import RiskLevel
from app.utils.storage import escape_format_chars


class FileOut(BaseModel):
    """File metadata. The file content is never returned by the API."""

    id: uuid.UUID
    original_filename: str
    size_bytes: int
    declared_mime: str | None
    detected_mime: str
    sha256: str
    created_at: datetime
    status: str  # UPLOADED until a scan exists, then the latest scan's status
    risk_level: RiskLevel | None

    @field_serializer("original_filename")
    def _escape_invisible(self, value: str) -> str:
        return escape_format_chars(value)
