import uuid
from collections.abc import Iterable

from fastapi import UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppError, ConflictError, FileTooLargeError, NotFoundError
from app.db.models import File, Scan, ScanStatus, User, UserRole
from app.schemas.file import FileOut
from app.services import audit_service
from app.services.audit_service import AuditAction
from app.utils.filetype import detect_mime
from app.utils.hashing import StreamHasher
from app.utils.storage import FileStorage, clean_filename, new_stored_name

UPLOAD_CHUNK_SIZE = 64 * 1024
ACTIVE_STATUSES = (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value)


class EmptyFileError(AppError):
    status_code = 400
    code = "EMPTY_FILE"
    message = "Uploaded file is empty"


def _clean_declared_mime(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable())[:255]
    return cleaned or None


async def save_upload(
    session: AsyncSession, storage: FileStorage, owner: User, upload: UploadFile,
    *, max_bytes: int, ip: str | None = None,
) -> File:
    """Stream the upload to disk (size-limited), hash it, detect its real type, record it."""
    filename = clean_filename(upload.filename)
    stored_name = new_stored_name()
    hasher = StreamHasher()
    try:
        with storage.open_new(stored_name) as out:
            while chunk := await upload.read(UPLOAD_CHUNK_SIZE):
                hasher.update(chunk)
                if hasher.size > max_bytes:
                    raise FileTooLargeError()
                out.write(chunk)
        if hasher.size == 0:
            raise EmptyFileError()

        file = File(
            owner_id=owner.id,
            original_filename=filename,
            stored_name=stored_name,
            size_bytes=hasher.size,
            declared_mime=_clean_declared_mime(upload.content_type),
            detected_mime=detect_mime(storage.path_for(stored_name)),
            sha256=hasher.hexdigest(),
        )
        session.add(file)
        await session.commit()
    except Exception:
        await session.rollback()
        storage.delete(stored_name)  # never leave orphaned or partial files behind
        raise

    await audit_service.record(
        session, AuditAction.FILE_UPLOADED, user_id=owner.id, ip=ip,
        details={"file_id": str(file.id), "filename": file.original_filename,
                 "size_bytes": file.size_bytes, "sha256": file.sha256,
                 "detected_mime": file.detected_mime},
    )
    return file


async def get_file_for_user(
    session: AsyncSession, user: User, file_id: uuid.UUID, *, allow_admin: bool = True
) -> File:
    """Owner (or admin) only. Others get 404, so file existence is not leaked."""
    file = await session.get(File, file_id)
    if file is None:
        raise NotFoundError("File not found")
    is_owner = file.owner_id == user.id
    is_admin = allow_admin and user.role == UserRole.ADMIN.value
    if not (is_owner or is_admin):
        raise NotFoundError("File not found")
    return file


async def latest_scans(session: AsyncSession, file_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, Scan]:
    ids = list(file_ids)
    if not ids:
        return {}
    rows = (
        await session.execute(
            select(Scan).where(Scan.file_id.in_(ids)).order_by(Scan.created_at.desc())
        )
    ).scalars()
    latest: dict[uuid.UUID, Scan] = {}
    for scan in rows:
        latest.setdefault(scan.file_id, scan)
    return latest


def to_file_out(file: File, scan: Scan | None) -> FileOut:
    return FileOut(
        id=file.id,
        original_filename=file.original_filename,
        size_bytes=file.size_bytes,
        declared_mime=file.declared_mime,
        detected_mime=file.detected_mime,
        sha256=file.sha256,
        created_at=file.created_at,
        status=scan.status if scan else "UPLOADED",
        risk_level=file.risk_level,
    )


async def list_files(session: AsyncSession, user: User, limit: int, offset: int) -> list[FileOut]:
    files = (
        await session.execute(
            select(File).where(File.owner_id == user.id)
            .order_by(File.created_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    scans = await latest_scans(session, [f.id for f in files])
    return [to_file_out(f, scans.get(f.id)) for f in files]


async def delete_file(
    session: AsyncSession, storage: FileStorage, user: User, file_id: uuid.UUID,
    *, ip: str | None = None,
) -> None:
    file = await get_file_for_user(session, user, file_id)
    active = await session.scalar(
        select(func.count()).select_from(Scan)
        .where(Scan.file_id == file.id, Scan.status.in_(ACTIVE_STATUSES))
    )
    if active:
        raise ConflictError("File has a scan in progress")

    owner_id, stored_name = file.owner_id, file.stored_name
    details = {"file_id": str(file.id), "owner_id": str(owner_id), "sha256": file.sha256}
    await session.delete(file)
    await session.commit()
    storage.delete(stored_name)

    action = AuditAction.FILE_DELETED if owner_id == user.id else AuditAction.ADMIN_DELETED_FILE
    await audit_service.record(session, action, user_id=user.id, ip=ip, details=details)
