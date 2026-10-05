import asyncio
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.services import scan_service
from app.utils.storage import get_storage
from app.workers.celery_app import celery_app


async def _run(scan_id: str) -> None:
    # A fresh engine per task: asyncio.run() creates a new event loop each time,
    # and async connections must not outlive the loop they were created in.
    engine = create_async_engine(get_settings().DATABASE_URL, poolclass=NullPool)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        await scan_service.execute_scan(factory, get_storage(), uuid.UUID(scan_id))
    finally:
        await engine.dispose()


@celery_app.task(name="scans.run_scan")
def run_scan(scan_id: str) -> None:
    asyncio.run(_run(scan_id))


def dispatch_scan(scan_id: uuid.UUID) -> None:
    """Queue a scan. Raises if the broker is unreachable (the API turns that into 503)."""
    run_scan.delay(str(scan_id))
