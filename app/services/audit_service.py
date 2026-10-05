import enum
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import request_id_var
from app.db.models import AuditLog


class AuditAction(str, enum.Enum):
    USER_REGISTERED = "USER_REGISTERED"
    USER_LOGIN = "USER_LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_DELETED = "FILE_DELETED"
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    ADMIN_VIEWED_AUDIT = "ADMIN_VIEWED_AUDIT"
    ADMIN_DELETED_FILE = "ADMIN_DELETED_FILE"


# Defence in depth: keys that must never be persisted in audit details,
# even if a caller passes them by mistake.
_FORBIDDEN_KEY_FRAGMENTS = (
    "password", "passwd", "token", "jwt", "secret", "authorization",
    "api_key", "apikey", "content", "evidence", "credential",
)
_MAX_VALUE_LENGTH = 200


def sanitize_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    if not details:
        return None
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if any(fragment in key.lower() for fragment in _FORBIDDEN_KEY_FRAGMENTS):
            continue
        if isinstance(value, str) and len(value) > _MAX_VALUE_LENGTH:
            value = value[:_MAX_VALUE_LENGTH] + "..."
        clean[key] = value
    return clean or None


async def record(
    session: AsyncSession,
    action: AuditAction,
    *,
    user_id: uuid.UUID | None = None,
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    request_id = request_id_var.get()
    entry = AuditLog(
        user_id=user_id,
        action=action.value,
        ip_address=ip,
        request_id=None if request_id == "-" else request_id,
        details=sanitize_details(details),
    )
    session.add(entry)
    await session.commit()
    return entry
