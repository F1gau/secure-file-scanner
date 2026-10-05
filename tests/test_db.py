import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.models import (
    AuditLog,
    Base,
    File,
    Finding,
    RiskLevel,
    Scan,
    ScanStatus,
    Severity,
    User,
    UserRole,
)


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_conn, _):  # SQLite ignores FKs unless enabled
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as s:
        yield s
    await engine.dispose()


def make_user(email="user@example.com", role=UserRole.USER.value):
    return User(email=email, hashed_password="not-a-real-hash", role=role)


def make_file(owner, sha="a" * 64, stored="stored-1"):
    return File(owner_id=owner.id, original_filename="report.pdf", stored_name=stored,
                size_bytes=123, detected_mime="application/pdf", sha256=sha)


async def test_user_defaults(session):
    u = make_user()
    session.add(u)
    await session.commit()
    assert u.id is not None
    assert u.role == "USER"
    assert u.is_active is True
    assert u.created_at is not None


async def test_email_must_be_unique(session):
    session.add(make_user())
    await session.commit()
    session.add(make_user())
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_stored_name_must_be_unique(session):
    u = make_user()
    session.add(u)
    await session.commit()
    session.add_all([make_file(u, stored="same"), make_file(u, stored="same")])
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_file_requires_existing_owner(session):
    import uuid

    session.add(File(owner_id=uuid.uuid4(), original_filename="a.txt", stored_name="x",
                     size_bytes=1, detected_mime="text/plain", sha256="b" * 64))
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_scan_defaults_to_queued(session):
    u = make_user()
    session.add(u)
    await session.commit()
    f = make_file(u)
    session.add(f)
    await session.commit()
    scan = Scan(file_id=f.id)
    session.add(scan)
    await session.commit()
    assert scan.status == ScanStatus.QUEUED.value
    assert scan.risk_score is None
    assert scan.finished_at is None


async def test_relationships_user_file_scan_finding(session):
    u = make_user()
    session.add(u)
    await session.commit()
    f = make_file(u)
    session.add(f)
    await session.commit()
    scan = Scan(file_id=f.id)
    session.add(scan)
    await session.commit()
    fd = Finding(scan_id=scan.id, scanner="filename", rule="DOUBLE_EXTENSION",
                 severity=Severity.HIGH.value, description="Double extension",
                 evidence="report.pdf.exe", confidence=0.9)
    session.add(fd)
    await session.commit()

    found = (await session.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    assert [x.rule for x in found] == ["DOUBLE_EXTENSION"]
    assert found[0].confidence == 0.9


async def test_deleting_file_cascades_to_scans_and_findings(session):
    u = make_user()
    session.add(u)
    await session.commit()
    f = make_file(u)
    session.add(f)
    await session.commit()
    scan = Scan(file_id=f.id)
    session.add(scan)
    await session.commit()
    session.add(Finding(scan_id=scan.id, scanner="s", rule="R", severity="LOW", description="d"))
    await session.commit()

    await session.delete(f)
    await session.commit()

    assert (await session.execute(select(Scan))).scalars().all() == []
    assert (await session.execute(select(Finding))).scalars().all() == []


async def test_deleting_user_cascades_to_files(session):
    u = make_user()
    session.add(u)
    await session.commit()
    session.add(make_file(u))
    await session.commit()
    await session.delete(u)
    await session.commit()
    assert (await session.execute(select(File))).scalars().all() == []


async def test_audit_log_survives_user_deletion(session):
    u = make_user()
    session.add(u)
    await session.commit()
    session.add(AuditLog(user_id=u.id, action="USER_LOGIN", details={"ok": True}))
    await session.commit()

    await session.delete(u)
    await session.commit()

    log = (await session.execute(select(AuditLog))).scalar_one()
    assert log.user_id is None
    assert log.action == "USER_LOGIN"
    assert log.details == {"ok": True}


async def test_enum_values_match_spec():
    assert {s.value for s in ScanStatus} == {"QUEUED", "RUNNING", "COMPLETED", "FAILED", "REJECTED"}
    assert {r.value for r in RiskLevel} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert {r.value for r in UserRole} == {"USER", "ADMIN"}
