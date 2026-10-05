import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from app.db.models import Severity
from app.utils.storage import escape_format_chars

MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_EVIDENCE_LENGTH = 200


@dataclass(frozen=True)
class Finding:
    scanner: str
    rule: str
    severity: Severity
    description: str
    evidence: str | None = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass
class ScanContext:
    """Everything a scanner may look at. Files are only ever read, never executed."""

    path: Path
    original_filename: str
    declared_mime: str | None
    detected_mime: str
    size_bytes: int
    max_archive_files: int = 500
    max_extracted_size: int = 100 * 1024 * 1024
    max_archive_depth: int = 2
    max_text_bytes: int = MAX_TEXT_BYTES

    def read_text(self) -> str:
        with open(self.path, "rb") as f:
            raw = f.read(self.max_text_bytes)
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16", errors="replace")
        return raw.decode("utf-8-sig", errors="replace")


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        """Return findings for the file. Must not execute the file or raise on bad input."""


def safe_evidence(text: str, limit: int = MAX_EVIDENCE_LENGTH) -> str:
    """Printable, bounded evidence string (control/format characters made visible)."""
    cleaned = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in text)
    cleaned = escape_format_chars(cleaned)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
