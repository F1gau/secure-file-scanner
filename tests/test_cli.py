import pytest
from sqlalchemy import select

from app.cli import create_admin
from app.core.exceptions import ConflictError
from app.db.models import AuditLog, User


async def test_create_admin_creates_admin_role(session_factory):
    user = await create_admin(session_factory, "Root@Example.com", "long-enough-password")
    assert user.role == "ADMIN"
    assert user.email == "root@example.com"


async def test_create_admin_writes_audit_entry(session_factory):
    await create_admin(session_factory, "root@example.com", "long-enough-password")
    async with session_factory() as s:
        row = (await s.execute(select(AuditLog))).scalar_one()
    assert row.action == "USER_REGISTERED"
    assert row.details == {"via": "cli", "role": "ADMIN"}


async def test_create_admin_rejects_weak_password(session_factory):
    with pytest.raises(ValueError):
        await create_admin(session_factory, "root@example.com", "short")
    async with session_factory() as s:
        assert (await s.execute(select(User))).scalars().all() == []


async def test_create_admin_duplicate_email(session_factory):
    await create_admin(session_factory, "root@example.com", "long-enough-password")
    with pytest.raises(ConflictError):
        await create_admin(session_factory, "root@example.com", "long-enough-password")


async def test_created_admin_can_log_in(client, session_factory):
    await create_admin(session_factory, "root@example.com", "long-enough-password")
    r = await client.post(
        "/api/v1/auth/login", json={"email": "root@example.com", "password": "long-enough-password"}
    )
    assert r.status_code == 200
