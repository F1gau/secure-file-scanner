from sqlalchemy import select

from app.db.models import AuditLog
from app.services import audit_service
from app.services.audit_service import AuditAction, sanitize_details


def test_sanitize_none_and_empty():
    assert sanitize_details(None) is None
    assert sanitize_details({}) is None


def test_sanitize_drops_sensitive_keys():
    clean = sanitize_details({
        "password": "p", "new_password": "p", "access_token": "t", "JWT": "j",
        "api_key": "k", "Authorization": "Bearer x", "file_content": "c",
        "evidence": "sk_live_x", "client_secret": "s", "reason": "ok", "filename": "a.txt",
    })
    assert clean == {"reason": "ok", "filename": "a.txt"}


def test_sanitize_returns_none_if_everything_dropped():
    assert sanitize_details({"password": "x"}) is None


def test_sanitize_truncates_long_values():
    clean = sanitize_details({"note": "x" * 1000})
    assert len(clean["note"]) < 250


def test_sanitize_keeps_non_string_values():
    assert sanitize_details({"count": 3, "ok": True}) == {"count": 3, "ok": True}


async def test_record_persists_and_sanitizes(session_factory):
    async with session_factory() as s:
        await audit_service.record(
            s, AuditAction.FILE_UPLOADED, ip="10.0.0.1",
            details={"filename": "a.txt", "password": "should-not-be-stored"},
        )
    async with session_factory() as s:
        row = (await s.execute(select(AuditLog))).scalar_one()
    assert row.action == "FILE_UPLOADED"
    assert row.ip_address == "10.0.0.1"
    assert row.details == {"filename": "a.txt"}
    assert "should-not-be-stored" not in str(row.details)


def test_all_spec_actions_exist():
    expected = {
        "USER_REGISTERED", "USER_LOGIN", "LOGIN_FAILED", "FILE_UPLOADED", "FILE_DELETED",
        "SCAN_CREATED", "SCAN_COMPLETED", "SCAN_FAILED", "ADMIN_VIEWED_AUDIT",
        "ADMIN_DELETED_FILE",
    }
    assert {a.value for a in AuditAction} == expected
