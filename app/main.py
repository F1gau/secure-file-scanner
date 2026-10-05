import logging
import re
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app.api import admin, auth, files, health, scans
from app.core.config import get_settings
from app.core.exceptions import error_body, register_exception_handlers
from app.core.logging import request_id_var, setup_logging, user_id_var

logger = logging.getLogger("app.request")

# Accept only short, safe client-supplied request IDs; otherwise generate one.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
UPLOAD_PATH = "/api/v1/files"
MULTIPART_OVERHEAD_BYTES = 1024 * 1024  # headers/boundaries on top of the file itself


def normalize_request_id(value: str | None) -> str:
    if value and _REQUEST_ID_RE.fullmatch(value):
        return value
    return uuid.uuid4().hex


def _declared_body_too_large(request: Request, max_file_bytes: int) -> bool:
    """Reject obviously oversized uploads from the Content-Length header, before reading the body."""
    if request.method != "POST" or request.url.path != UPLOAD_PATH:
        return False
    try:
        declared = int(request.headers.get("content-length", "0"))
    except ValueError:
        return False
    return declared > max_file_bytes + MULTIPART_OVERHEAD_BYTES


def create_app() -> FastAPI:
    settings = get_settings()
    settings.validate_for_runtime()
    setup_logging(settings.LOG_LEVEL)

    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        description=(
            "Educational security-oriented file scanner API. It is not an antivirus. "
            "Uploaded files are analyzed statically and are never executed by the application."
        ),
    )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = normalize_request_id(request.headers.get("X-Request-ID"))
        token = request_id_var.set(rid)
        try:
            if _declared_body_too_large(request, settings.max_file_size_bytes):
                response: Response = JSONResponse(
                    error_body("FILE_TOO_LARGE", "File exceeds configured size limit"),
                    status_code=413,
                )
            else:
                response = await call_next(request)
            # The user id is set in a dependency (another task), so read it from request.state.
            user_token = user_id_var.set(getattr(request.state, "user_id", "-"))
            try:
                logger.info("request_completed method=%s path=%s status=%s",
                            request.method, request.url.path, response.status_code)
            finally:
                user_id_var.reset(user_token)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response

    register_exception_handlers(app)
    app.include_router(health.router)
    for router in (auth.router, files.router, scans.router, admin.router, admin.stats_router):
        app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
