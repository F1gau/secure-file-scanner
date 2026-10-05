import uuid

import pytest
from sqlalchemy import select

from app.db.models import AuditLog, UserRole
from tests import helpers as h

ADMIN_EMAIL = "root@example.com"
OTHER = "other@example.com"


@pytest.fixture
async def admin(create_user, auth_headers):
    await create_user(ADMIN_EMAIL, role=UserRole.ADMIN)
    return await auth_headers(ADMIN_EMAIL)


@pytest.fixture
async def user(create_user, auth_headers):
    await create_user()
    return await auth_headers()


ADMIN_ENDPOINTS = ["/api/v1/admin/users", "/api/v1/admin/scans", "/api/v1/admin/audit", "/api/v1/stats"]


@pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
async def test_admin_endpoints_reject_anonymous(client, path):
    assert (await client.get(path)).status_code == 401


@pytest.mark.parametrize("path", ADMIN_ENDPOINTS)
async def test_admin_endpoints_reject_regular_user(client, user, path):
    r = await client.get(path, headers=user)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"


async def test_admin_lists_users_without_password_data(client, admin, user):
    r = await client.get("/api/v1/admin/users", headers=admin)
    assert r.status_code == 200
    assert {u["email"] for u in r.json()} == {ADMIN_EMAIL, "user@example.com"}
    assert "password" not in r.text.lower() and "hash" not in r.text.lower()


async def test_admin_sees_all_scans_with_owner(client, admin, user, upload, run_scan):
    file_id = (await upload(user, b"x", "a.txt")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=user, json={"file_id": file_id})).json()
    await run_scan(scan["id"])
    r = await client.get("/api/v1/admin/scans", headers=admin)
    assert r.status_code == 200 and r.json()[0]["id"] == scan["id"] and r.json()[0]["owner_id"]
    assert (await client.get("/api/v1/admin/scans", headers=admin,
                             params={"status": "FAILED"})).json() == []
    assert len((await client.get("/api/v1/admin/scans", headers=admin,
                                 params={"risk_level": "LOW"})).json()) == 1


async def test_admin_can_read_other_users_file_and_scan(client, admin, user, upload):
    file_id = (await upload(user, b"x", "a.txt")).json()["id"]
    assert (await client.get(f"/api/v1/files/{file_id}", headers=admin)).status_code == 200


async def test_admin_cannot_start_scan_for_other_users_file(client, admin, user, upload):
    file_id = (await upload(user, b"x", "a.txt")).json()["id"]
    r = await client.post("/api/v1/scans", headers=admin, json={"file_id": file_id})
    assert r.status_code == 404


async def test_admin_can_delete_suspicious_file_and_it_is_audited(client, admin, user, upload, storage,
                                                                  session_factory):
    file_id = (await upload(user, h.PE_BYTES, "x.pdf.exe")).json()["id"]
    assert (await client.delete(f"/api/v1/files/{file_id}", headers=admin)).status_code == 204
    assert list(storage.root.iterdir()) == []
    assert (await client.get(f"/api/v1/files/{file_id}", headers=user)).status_code == 404
    async with session_factory() as s:
        actions = [a.action for a in (await s.execute(select(AuditLog))).scalars()]
    assert "ADMIN_DELETED_FILE" in actions and "FILE_DELETED" not in actions


async def test_reading_audit_log_is_itself_audited(client, admin, user, session_factory):
    r = await client.get("/api/v1/admin/audit", headers=admin)
    assert r.status_code == 200
    assert {e["action"] for e in r.json()} >= {"USER_LOGIN"}
    async with session_factory() as s:
        viewed = (await s.execute(
            select(AuditLog).where(AuditLog.action == "ADMIN_VIEWED_AUDIT"))).scalars().all()
    assert len(viewed) == 1 and viewed[0].details["returned"] == len(r.json())


async def test_audit_filters(client, admin, user):
    only_logins = (await client.get("/api/v1/admin/audit", headers=admin,
                                    params={"action": "USER_LOGIN"})).json()
    assert only_logins and {e["action"] for e in only_logins} == {"USER_LOGIN"}
    assert (await client.get("/api/v1/admin/audit", headers=admin,
                             params={"action": "NOPE"})).status_code == 422
    assert (await client.get("/api/v1/admin/audit", headers=admin,
                             params={"user_id": str(uuid.uuid4())})).json() == []


async def test_stats_counts(client, admin, user, upload, run_scan):
    ok = (await upload(user, b"x", "a.txt")).json()["id"]
    bad = (await upload(user, h.PE_BYTES, "x.pdf.exe")).json()["id"]
    for fid in (ok, bad):
        scan = (await client.post("/api/v1/scans", headers=user, json={"file_id": fid})).json()
        await run_scan(scan["id"])
    stats = (await client.get("/api/v1/stats", headers=admin)).json()
    assert stats["total_files"] == 2 and stats["total_scans"] == 2
    assert stats["critical_scans"] == 1 and stats["failed_scans"] == 0
    assert stats["high_risk_scans"] == 0
    assert stats["average_scan_time_seconds"] is not None and stats["average_scan_time_seconds"] >= 0


async def test_stats_on_empty_system(client, admin):
    stats = (await client.get("/api/v1/stats", headers=admin)).json()
    assert stats == {"total_files": 0, "total_scans": 0, "high_risk_scans": 0, "critical_scans": 0,
                     "failed_scans": 0, "average_scan_time_seconds": None}


async def test_pagination_limits_validated(client, admin):
    assert (await client.get("/api/v1/admin/users", headers=admin, params={"limit": 0})).status_code == 422
    assert (await client.get("/api/v1/admin/audit", headers=admin, params={"offset": -1})).status_code == 422
