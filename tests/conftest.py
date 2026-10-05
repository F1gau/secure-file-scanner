import os

# Set test environment before the app is imported.
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-not-for-production-use")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6399/0")
os.environ.setdefault("BCRYPT_ROUNDS", "4")  # fast hashing in tests only

import uuid  # noqa: E402

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.database import get_session  # noqa: E402
from app.db.models import Base, UserRole  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import auth_service  # noqa: E402
from app.services.rate_limit import InMemoryRateLimiter, get_rate_limiter  # noqa: E402
from app.utils.storage import FileStorage, get_storage  # noqa: E402
from app.workers import scan_tasks  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng.sync_engine, "connect")
    def _fk_on(dbapi_conn, _):  # SQLite ignores foreign keys unless enabled
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def limiter():
    return InMemoryRateLimiter()


@pytest.fixture
def storage(tmp_path):
    return FileStorage(tmp_path / "storage")


@pytest.fixture
def queued_scans(monkeypatch):
    """Replace the Celery dispatch with a recorder; tests run the scan explicitly."""
    queued: list[uuid.UUID] = []
    monkeypatch.setattr(scan_tasks, "dispatch_scan", lambda scan_id: queued.append(scan_id))
    return queued


@pytest.fixture
def app(session_factory, limiter, storage, queued_scans):
    """A fresh application per test, wired to the in-memory DB, rate limiter and temp storage."""
    application = create_app()

    async def _get_session():
        async with session_factory() as s:
            yield s

    application.dependency_overrides[get_session] = _get_session
    application.dependency_overrides[get_rate_limiter] = lambda: limiter
    application.dependency_overrides[get_storage] = lambda: storage
    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def create_user(session_factory):
    async def _create(email="user@example.com", password=PASSWORD, role=UserRole.USER):
        async with session_factory() as s:
            return await auth_service.create_user(s, email, password, role=role)

    return _create


@pytest.fixture
def auth_headers(client):
    async def _login(email="user@example.com", password=PASSWORD) -> dict[str, str]:
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _login


@pytest.fixture
def upload(client):
    async def _upload(headers, content=b"hello world\n", filename="note.txt",
                      content_type="text/plain"):
        return await client.post(
            "/api/v1/files", headers=headers, files={"file": (filename, content, content_type)}
        )

    return _upload


@pytest.fixture
def run_scan(session_factory, storage):
    from app.services import scan_service

    async def _run(scan_id):
        return await scan_service.execute_scan(session_factory, storage, uuid.UUID(str(scan_id)))

    return _run
