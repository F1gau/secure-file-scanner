import asyncio
import logging
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_client_ip, get_current_user, get_session
from app.core.exceptions import AppError
from app.db.models import ScanStatus, User
from app.schemas.common import ErrorResponse
from app.schemas.scan import FindingOut, ScanCreate, ScanOut
from app.services import scan_service
from app.workers import scan_tasks

logger = logging.getLogger("app.api.scans")
router = APIRouter(prefix="/scans", tags=["scans"])

_AUTH_ERRORS = {401: {"model": ErrorResponse, "description": "Missing or invalid token"}}
_NOT_FOUND = {404: {"model": ErrorResponse, "description": "Scan not found"}}


@router.post(
    "",
    response_model=ScanOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a scan of an uploaded file",
    description="Creates a QUEUED scan and hands it to the background worker. "
                "Poll GET /api/v1/scans/{scan_id} for the result.",
    responses={
        **_AUTH_ERRORS,
        404: {"model": ErrorResponse, "description": "File not found"},
        409: {"model": ErrorResponse, "description": "A scan is already queued or running"},
        503: {"model": ErrorResponse, "description": "Scan queue unavailable"},
    },
)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanOut:
    scan = await scan_service.create_scan(session, user, payload.file_id, ip=get_client_ip(request))
    try:
        await asyncio.to_thread(scan_tasks.dispatch_scan, scan.id)
    except Exception as exc:  # noqa: BLE001 - broker down, serialization, etc.
        logger.error("scan_enqueue_failed error_type=%s", type(exc).__name__, exc_info=exc)
        await scan_service.fail_scan(session, scan.id, user.id, "Could not enqueue scan")
        raise AppError("Scan queue is unavailable", code="QUEUE_UNAVAILABLE",
                       status_code=503) from None
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut], summary="List my scans", responses=_AUTH_ERRORS)
async def list_scans(
    status_filter: ScanStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[ScanOut]:
    scans = await scan_service.list_scans_for_user(
        session, user, status=status_filter, limit=limit, offset=offset
    )
    return [ScanOut.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut, summary="Get scan status and risk",
            responses={**_AUTH_ERRORS, **_NOT_FOUND})
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> ScanOut:
    return ScanOut.model_validate(await scan_service.get_scan_for_user(session, user, scan_id))


@router.get("/{scan_id}/findings", response_model=list[FindingOut],
            summary="List findings of a scan",
            description="Most severe first. Evidence is masked and never contains full secrets.",
            responses={**_AUTH_ERRORS, **_NOT_FOUND})
async def get_findings(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[FindingOut]:
    scan = await scan_service.get_scan_for_user(session, user, scan_id)
    findings = await scan_service.list_findings(session, scan.id)
    return [FindingOut.model_validate(f) for f in findings]
