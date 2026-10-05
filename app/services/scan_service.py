import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.exceptions import ConflictError, NotFoundError
from app.core.logging import scan_id_var
from app.db.models import File, Scan, ScanStatus, Severity, User, UserRole
from app.db.models import Finding as FindingModel
from app.scanners import BaseScanner, Finding, ScanContext, default_scanners
from app.scanners.archive import LIMIT_RULES
from app.services import audit_service, file_service, risk_service
from app.services.audit_service import AuditAction
from app.utils.storage import FileStorage, StorageError

logger = logging.getLogger("app.scans")

MAX_STORED_FINDINGS = 500
_SEVERITY_ORDER = {Severity.CRITICAL.value: 0, Severity.HIGH.value: 1,
                   Severity.MEDIUM.value: 2, Severity.LOW.value: 3}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScannerError(Exception):
    def __init__(self, scanner: str) -> None:
        super().__init__(scanner)
        self.scanner = scanner


def run_scanners(ctx: ScanContext, scanners: list[BaseScanner]) -> list[Finding]:
    """Run all scanners synchronously (called in a worker thread). Static analysis only."""
    results: list[Finding] = []
    for scanner in scanners:
        try:
            results.extend(scanner.scan(ctx))
        except Exception as exc:
            raise ScannerError(scanner.name) from exc
    return results


# ---------- API-side operations ----------

async def create_scan(
    session: AsyncSession, user: User, file_id: uuid.UUID, *, ip: str | None = None
) -> Scan:
    file = await file_service.get_file_for_user(session, user, file_id, allow_admin=False)
    active = await session.scalar(
        select(Scan.id).where(Scan.file_id == file.id,
                              Scan.status.in_(file_service.ACTIVE_STATUSES)).limit(1)
    )
    if active is not None:
        raise ConflictError("A scan for this file is already queued or running")

    scan = Scan(file_id=file.id)
    session.add(scan)
    await session.commit()
    await audit_service.record(
        session, AuditAction.SCAN_CREATED, user_id=user.id, ip=ip,
        details={"scan_id": str(scan.id), "file_id": str(file.id)},
    )
    return scan


async def get_scan_for_user(session: AsyncSession, user: User, scan_id: uuid.UUID) -> Scan:
    """Owner of the file (or admin) only; everybody else gets 404."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if user.role != UserRole.ADMIN.value:
        file = await session.get(File, scan.file_id)
        if file is None or file.owner_id != user.id:
            raise NotFoundError("Scan not found")
    return scan


async def list_scans_for_user(
    session: AsyncSession, user: User, *, status: ScanStatus | None, limit: int, offset: int
) -> list[Scan]:
    query = select(Scan).join(File, File.id == Scan.file_id).where(File.owner_id == user.id)
    if status is not None:
        query = query.where(Scan.status == status.value)
    result = await session.execute(query.order_by(Scan.created_at.desc()).limit(limit).offset(offset))
    return list(result.scalars().all())


async def list_findings(session: AsyncSession, scan_id: uuid.UUID) -> list[FindingModel]:
    rows = (
        await session.execute(select(FindingModel).where(FindingModel.scan_id == scan_id))
    ).scalars().all()
    return sorted(rows, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), -f.confidence, f.rule))


async def fail_scan(
    session: AsyncSession, scan_id: uuid.UUID, owner_id: uuid.UUID | None, message: str
) -> None:
    """Mark a scan FAILED with a short, safe message (never a traceback)."""
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = ScanStatus.FAILED.value
    scan.error_message = message[:500]
    scan.finished_at = utcnow()
    await session.commit()
    await audit_service.record(
        session, AuditAction.SCAN_FAILED, user_id=owner_id,
        details={"scan_id": str(scan_id), "error": message},
    )


# ---------- worker-side operation ----------

async def execute_scan(
    session_factory: async_sessionmaker[AsyncSession], storage: FileStorage, scan_id: uuid.UUID,
    scanners: list[BaseScanner] | None = None,
) -> ScanStatus | None:
    """Run one queued scan to a terminal state. Safe to call twice: only QUEUED scans run."""
    token = scan_id_var.set(str(scan_id))
    try:
        return await _execute_scan(session_factory, storage, scan_id, scanners)
    finally:
        scan_id_var.reset(token)


async def _execute_scan(session_factory, storage, scan_id, scanners) -> ScanStatus | None:
    settings = get_settings()
    async with session_factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            logger.warning("scan_not_found")
            return None
        if scan.status != ScanStatus.QUEUED.value:
            logger.info("scan_skipped status=%s", scan.status)
            return None
        file = await session.get(File, scan.file_id)
        if file is None:
            return None
        owner_id, file_id, stored_name = file.owner_id, file.id, file.stored_name
        ctx = ScanContext(
            path=storage.root,  # replaced below once the path is validated
            original_filename=file.original_filename,
            declared_mime=file.declared_mime,
            detected_mime=file.detected_mime,
            size_bytes=file.size_bytes,
            max_archive_files=settings.MAX_ARCHIVE_FILES,
            max_extracted_size=settings.max_extracted_size_bytes,
            max_archive_depth=settings.MAX_ARCHIVE_DEPTH,
        )
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = utcnow()
        await session.commit()
    logger.info("scan_started")

    async def fail(message: str) -> ScanStatus:
        async with session_factory() as s:
            await fail_scan(s, scan_id, owner_id, message)
        return ScanStatus.FAILED

    try:
        ctx.path = storage.path_for(stored_name)
        if not ctx.path.is_file():
            raise FileNotFoundError(stored_name)
        findings = await asyncio.to_thread(run_scanners, ctx, scanners or default_scanners())
    except (FileNotFoundError, StorageError):
        logger.error("scan_file_unavailable")
        return await fail("Stored file is not available")
    except ScannerError as exc:
        logger.error("scan_scanner_failed scanner=%s", exc.scanner, exc_info=exc.__cause__)
        return await fail(f"Scanner '{exc.scanner}' failed")
    except Exception as exc:  # noqa: BLE001 - includes worker time limit
        logger.error("scan_unexpected_error error_type=%s", type(exc).__name__, exc_info=exc)
        return await fail("Internal error during scan")

    assessment = risk_service.assess(findings)
    status = (ScanStatus.REJECTED if any(f.rule in LIMIT_RULES for f in findings)
              else ScanStatus.COMPLETED)

    async with session_factory() as session:
        scan = await session.get(Scan, scan_id)
        file = await session.get(File, file_id)
        if scan is None or file is None:  # file was deleted while scanning
            return None
        for f in findings[:MAX_STORED_FINDINGS]:
            session.add(FindingModel(
                scan_id=scan_id, scanner=f.scanner, rule=f.rule, severity=f.severity.value,
                description=f.description, evidence=f.evidence, confidence=f.confidence,
            ))
        scan.status = status.value
        scan.risk_score = assessment.score
        scan.risk_level = assessment.level.value
        scan.finished_at = utcnow()
        file.risk_level = assessment.level.value
        await session.commit()
        await audit_service.record(
            session, AuditAction.SCAN_COMPLETED, user_id=owner_id,
            details={"scan_id": str(scan_id), "status": status.value,
                     "risk_score": assessment.score, "risk_level": assessment.level.value,
                     "findings": len(findings)},
        )
    logger.info("scan_finished status=%s risk_score=%s", status.value, assessment.score)
    return status

