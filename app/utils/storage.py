import os
import re
import unicodedata
import uuid
from pathlib import Path
from typing import BinaryIO

from app.core.config import get_settings

STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_FILENAME_LENGTH = 255


class StorageError(Exception):
    """Raised when a storage path would escape the storage directory."""


def clean_filename(raw: str | None) -> str:
    """Reduce a client-supplied filename to a harmless display name.

    - keeps only the last path component (handles both / and \\ separators),
    - drops NUL and other control characters,
    - never returns "", "." or "..".
    Format characters (e.g. the right-to-left override U+202E) are kept on purpose
    so the filename scanner can flag them; they are escaped on output.
    The cleaned name is metadata only: files are stored under a random name.
    """
    name = (raw or "").replace("\x00", "")
    parts = [p for p in re.split(r"[\\/]+", name) if p not in ("", ".", "..")]
    name = parts[-1] if parts else ""
    name = "".join(ch for ch in name if unicodedata.category(ch) != "Cc").strip()
    if len(name) > MAX_FILENAME_LENGTH:
        name = name[-MAX_FILENAME_LENGTH:]  # keep the extension
    return name or "unnamed"


def escape_format_chars(text: str) -> str:
    """Make invisible/bidi formatting characters visible (\\u202e) for API output and logs."""
    return "".join(
        f"\\u{ord(ch):04x}" if unicodedata.category(ch) in ("Cf", "Cc") else ch for ch in text
    )


def new_stored_name() -> str:
    return uuid.uuid4().hex


class FileStorage:
    """Flat directory of files named by random UUID. Never uses client input in paths."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path_for(self, stored_name: str) -> Path:
        if not STORED_NAME_RE.fullmatch(stored_name):
            raise StorageError("invalid stored name")
        path = (self.root / stored_name).resolve()
        if path.parent != self.root:  # also defeats symlink tricks
            raise StorageError("path escapes storage directory")
        return path

    def open_new(self, stored_name: str) -> BinaryIO:
        """Create a new file exclusively (never overwrites), owner-only permissions."""
        fd = os.open(self.path_for(stored_name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        return os.fdopen(fd, "wb")

    def exists(self, stored_name: str) -> bool:
        return self.path_for(stored_name).is_file()

    def delete(self, stored_name: str) -> bool:
        try:
            self.path_for(stored_name).unlink()
            return True
        except FileNotFoundError:
            return False


def get_storage() -> FileStorage:
    """FastAPI dependency / factory; overridden in tests with a temp directory."""
    return FileStorage(get_settings().STORAGE_PATH)
