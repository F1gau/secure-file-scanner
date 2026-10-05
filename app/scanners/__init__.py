from app.scanners.archive import ArchiveScanner
from app.scanners.base import BaseScanner, Finding, ScanContext
from app.scanners.file_type import FileTypeScanner
from app.scanners.filename import FilenameScanner
from app.scanners.pii import PiiScanner
from app.scanners.secrets import SecretsScanner


def default_scanners() -> list[BaseScanner]:
    return [FilenameScanner(), FileTypeScanner(), SecretsScanner(), PiiScanner(), ArchiveScanner()]


__all__ = ["BaseScanner", "Finding", "ScanContext", "default_scanners"]
