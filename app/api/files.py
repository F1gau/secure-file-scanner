import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, UploadFile, status
from fastapi import File as FormFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import enforce_upload_rate_limit, get_client_ip, get_current_user, get_session
from app.core.config import get_settings
from app.db.models import User
from app.schemas.common import ErrorResponse
from app.schemas.file import FileOut
from app.services import file_service
from app.utils.storage import FileStorage, get_storage

router = APIRouter(prefix="/files", tags=["files"])

_AUTH_ERRORS = {401: {"model": ErrorResponse, "description": "Missing or invalid token"}}


@router.post(
    "",
    response_model=FileOut,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a file",
    description=(
        "Stores the file under a random name, computes SHA-256 and detects the real type "
        "from the content (the client-supplied Content-Type is only recorded). "
        "Files are never executed. Start analysis with POST /api/v1/scans."
    ),
    dependencies=[Depends(enforce_upload_rate_limit)],
    responses={
        **_AUTH_ERRORS,
        400: {"model": ErrorResponse, "description": "Empty file"},
        413: {"model": ErrorResponse, "description": "File exceeds the size limit"},
        429: {"model": ErrorResponse, "description": "Too many upload requests"},
    },
)
async def upload_file(
    request: Request,
    file: UploadFile = FormFile(..., description="The file to analyze"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    storage: FileStorage = Depends(get_storage),
) -> FileOut:
    record = await file_service.save_upload(
        session, storage, user, file,
        max_bytes=get_settings().max_file_size_bytes, ip=get_client_ip(request),
    )
    return file_service.to_file_out(record, None)


@router.get("", response_model=list[FileOut], summary="List my files",
            responses=_AUTH_ERRORS)
async def list_files(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[FileOut]:
    return await file_service.list_files(session, user, limit, offset)


@router.get(
    "/{file_id}", response_model=FileOut, summary="Get file metadata",
    description="Returns metadata only (never the content). Other users' files return 404.",
    responses={**_AUTH_ERRORS, 404: {"model": ErrorResponse, "description": "File not found"}},
)
async def get_file(
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> FileOut:
    file = await file_service.get_file_for_user(session, user, file_id)
    scans = await file_service.latest_scans(session, [file.id])
    return file_service.to_file_out(file, scans.get(file.id))


@router.delete(
    "/{file_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a file",
    description="Owner or admin. Removes the stored file together with its scans and findings.",
    responses={
        **_AUTH_ERRORS,
        404: {"model": ErrorResponse, "description": "File not found"},
        409: {"model": ErrorResponse, "description": "A scan is in progress"},
    },
)
async def delete_file(
    file_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    storage: FileStorage = Depends(get_storage),
) -> Response:
    await file_service.delete_file(session, storage, user, file_id, ip=get_client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
