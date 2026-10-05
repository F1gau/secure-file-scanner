import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])
logger = logging.getLogger("app.health")


@router.get("/health", summary="Liveness probe",
            description="Returns 200 if the process is up. Does not touch dependencies.")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/health/ready", summary="Readiness probe",
            description="Checks connectivity to PostgreSQL and Redis. "
                        "Returns 503 if any dependency is unavailable.")
async def ready() -> JSONResponse:
    checks = {"database": await _check_database(), "redis": await _check_redis()}
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"status": "ready" if ok else "unavailable", "checks": checks},
        status_code=200 if ok else 503,
    )


async def _check_database() -> str:
    try:
        from sqlalchemy import text

        from app.db.database import get_engine

        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:  # noqa: BLE001 - report status only, no details
        logger.warning("readiness_database_failed error_type=%s", type(exc).__name__)
        return "unavailable"


async def _check_redis() -> str:
    try:
        from redis.asyncio import from_url

        from app.core.config import get_settings

        client = from_url(get_settings().REDIS_URL)
        try:
            await client.ping()
        finally:
            await client.aclose()
        return "ok"
    except Exception as exc:  # noqa: BLE001
        logger.warning("readiness_redis_failed error_type=%s", type(exc).__name__)
        return "unavailable"
