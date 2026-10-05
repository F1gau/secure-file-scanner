import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_client_ip, get_session, require_admin
from app.db.models import AuditLog, File, RiskLevel, Scan, ScanStatus, User
from app.schemas.admin import AdminScanOut, AuditLogOut, StatsOut
from app.schemas.common import ErrorResponse
from app.schemas.scan import ScanOut
from app.schemas.user import UserOut
from app.services import audit_service
from app.services.audit_service import AuditAction

_ADMIN_ERRORS = {
    401: {"model": ErrorResponse, "description": "Missing or invalid token"},
    403: {"model": ErrorResponse, "description": "Admin role required"},
}

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)],
                   responses=_ADMIN_ERRORS)
stats_router = APIRouter(tags=["admin"], dependencies=[Depends(require_admin)],
                         responses=_ADMIN_ERRORS)


@router.get("/users", response_model=list[UserOut], summary="List all users")
async def list_users(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[User]:
    result = await session.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


@router.get("/scans", response_model=list[AdminScanOut], summary="List all scans")
async def list_all_scans(
    status_filter: ScanStatus | None = Query(None, alias="status"),
    risk_level: RiskLevel | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> list[AdminScanOut]:
    query = select(Scan, File.owner_id).join(File, File.id == Scan.file_id)
    if status_filter is not None:
        query = query.where(Scan.status == status_filter.value)
    if risk_level is not None:
        query = query.where(Scan.risk_level == risk_level.value)
    rows = (
        await session.execute(query.order_by(Scan.created_at.desc()).limit(limit).offset(offset))
    ).all()
    return [
        AdminScanOut(**ScanOut.model_validate(scan).model_dump(), owner_id=owner_id)
        for scan, owner_id in rows
    ]


@router.get("/audit", response_model=list[AuditLogOut], summary="Read the audit log",
            description="Reading the audit log is itself audited (ADMIN_VIEWED_AUDIT).")
async def read_audit(
    request: Request,
    action: AuditAction | None = Query(None),
    user_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[AuditLog]:
    query = select(AuditLog)
    if action is not None:
        query = query.where(AuditLog.action == action.value)
    if user_id is not None:
        query = query.where(AuditLog.user_id == user_id)
    entries = list(
        (await session.execute(
            query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        )).scalars().all()
    )
    await audit_service.record(
        session, AuditAction.ADMIN_VIEWED_AUDIT, user_id=admin.id, ip=get_client_ip(request),
        details={"action_filter": action.value if action else None,
                 "user_filter": str(user_id) if user_id else None,
                 "returned": len(entries)},
    )
    return entries


@stats_router.get("/stats", response_model=StatsOut, summary="Platform statistics")
async def stats(session: AsyncSession = Depends(get_session)) -> StatsOut:
    async def count(query) -> int:
        return int(await session.scalar(query) or 0)

    def scans_where(*conditions):
        return select(func.count()).select_from(Scan).where(*conditions)

    total_files = await count(select(func.count()).select_from(File))
    durations = (
        await session.execute(
            select(Scan.started_at, Scan.finished_at)
            .where(Scan.started_at.is_not(None), Scan.finished_at.is_not(None))
            .order_by(Scan.finished_at.desc()).limit(1000)
        )
    ).all()
    seconds = [(end - start).total_seconds() for start, end in durations]
    return StatsOut(
        total_files=total_files,
        total_scans=await count(scans_where()),
        high_risk_scans=await count(scans_where(Scan.risk_level == RiskLevel.HIGH.value)),
        critical_scans=await count(scans_where(Scan.risk_level == RiskLevel.CRITICAL.value)),
        failed_scans=await count(scans_where(Scan.status == ScanStatus.FAILED.value)),
        average_scan_time_seconds=round(sum(seconds) / len(seconds), 3) if seconds else None,
    )
