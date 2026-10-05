"""Integration tests against real services. Skipped unless INTEGRATION_DATABASE_URL is set.

In CI: PostgreSQL and Redis run as service containers, `alembic upgrade head` is applied
before pytest, and these tests exercise the same code paths on the real stack.
Locally:  INTEGRATION_DATABASE_URL=postgresql+asyncpg://scanner:scanner@localhost:5432/scanner \
          INTEGRATION_REDIS_URL=redis://localhost:6379/0 pytest tests/test_integration.py
"""
import os
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.db.database import enable_sqlite_foreign_keys, get_session
from app.db.models import AuditLog, File, Finding, Scan
from app.main import create_app
from app.services import scan_service
from app.services.rate_limit import RedisRateLimiter, get_rate_limiter
from app.utils.storage import FileStorage, get_storage
from app.workers import scan_tasks
from tests import helpers as h

DB_URL = os.environ.get("INTEGRATION_DATABASE_URL")
REDIS_URL = os.environ.get("INTEGRATION_REDIS_URL")

pytestmark = pytest.mark.skipif(not DB_URL, reason="INTEGRATION_DATABASE_URL not set")

PASSWORD = "correct-horse-battery"


@pytest.fixture
async def real_factory():
    engine = create_async_engine(DB_URL, poolclass=NullPool)
    enable_sqlite_foreign_keys(engine)  # no-op on PostgreSQL
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def test_database_is_migrated_and_reachable(real_factory):
    async with real_factory() as s:
        assert await s.scalar(text("SELECT 1")) == 1
        for model in (File, Scan, Finding, AuditLog):
            assert await s.scalar(select(func.count()).select_from(model)) is not None


@pytest.mark.skipif(not REDIS_URL, reason="INTEGRATION_REDIS_URL not set")
async def test_redis_rate_limiter_against_real_redis():
    limiter = RedisRateLimiter(REDIS_URL)
    scope, ident = f"itest-{uuid.uuid4().hex}", "1.2.3.4"
    results = [await limiter.hit(scope, ident, limit=3, window_seconds=30) for _ in range(5)]
    assert [r.allowed for r in results] == [True, True, True, False, False]
    assert 1 <= results[-1].retry_after <= 30
    assert (await limiter.hit(scope, "other-ip", limit=3, window_seconds=30)).allowed


async def test_full_flow_on_real_database(real_factory, tmp_path, monkeypatch):
    queued: list[uuid.UUID] = []
    monkeypatch.setattr(scan_tasks, "dispatch_scan", lambda sid: queued.append(sid))
    storage = FileStorage(tmp_path / "storage")

    app = create_app()

    async def _session():
        async with real_factory() as s:
            yield s

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_storage] = lambda: storage
    if REDIS_URL:
        limiter = RedisRateLimiter(REDIS_URL)
        app.dependency_overrides[get_rate_limiter] = lambda: limiter

    email = f"it-{uuid.uuid4().hex[:10]}@example.com"
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD})
        assert r.status_code == 201, r.text
        token = (await client.post("/api/v1/auth/login",
                                   json={"email": email, "password": PASSWORD})).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert (await client.get("/api/v1/auth/me", headers=headers)).json()["email"] == email

        up = await client.post("/api/v1/files", headers=headers,
                               files={"file": ("report.pdf.exe", h.PE_BYTES, "application/pdf")})
        assert up.status_code == 201, up.text
        file_id = up.json()["id"]

        scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
        assert scan["status"] == "QUEUED" and queued == [uuid.UUID(scan["id"])]
        await scan_service.execute_scan(real_factory, storage, uuid.UUID(scan["id"]))

        done = (await client.get(f"/api/v1/scans/{scan['id']}", headers=headers)).json()
        assert done["status"] == "COMPLETED" and done["risk_level"] == "CRITICAL"
        rules = {f["rule"] for f in (await client.get(
            f"/api/v1/scans/{scan['id']}/findings", headers=headers)).json()}
        assert {"DOUBLE_EXTENSION", "DANGEROUS_EXTENSION"} <= rules
        assert (await client.get(f"/api/v1/files/{file_id}", headers=headers)).json()["status"] == "COMPLETED"

        assert (await client.delete(f"/api/v1/files/{file_id}", headers=headers)).status_code == 204
        assert (await client.get(f"/api/v1/scans/{scan['id']}", headers=headers)).status_code == 404

    async with real_factory() as s:  # cascade delete worked on the real database
        assert await s.scalar(select(func.count()).select_from(Scan).where(Scan.id == uuid.UUID(scan["id"]))) == 0
        actions = {a for (a,) in (await s.execute(select(AuditLog.action))).all()}
    assert {"USER_REGISTERED", "USER_LOGIN", "FILE_UPLOADED", "SCAN_CREATED",
            "SCAN_COMPLETED", "FILE_DELETED"} <= actions
