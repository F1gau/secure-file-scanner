import io
import zipfile
from dataclasses import dataclass

from app.db.models import Severity
from app.scanners.base import BaseScanner, Finding, ScanContext, safe_evidence
from app.scanners.filename import EXECUTABLE_EXTENSIONS, DANGEROUS_EXTENSIONS
from app.utils.filetype import ZIP_MIME, extension_of

# Findings with these rules make the whole scan end as REJECTED.
LIMIT_RULES = frozenset({
    "ARCHIVE_TOO_MANY_FILES", "ARCHIVE_TOO_LARGE", "ZIP_BOMB_SUSPECTED", "ARCHIVE_DEPTH_EXCEEDED",
})

MAX_COMPRESSION_RATIO = 100
MIN_SIZE_FOR_RATIO_CHECK = 1024 * 1024
MAX_NESTED_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_NAMES_LISTED = 5


@dataclass
class _State:
    files: int = 0
    declared_total: int = 0
    read_budget: int = 0
    stop: bool = False


class ArchiveScanner(BaseScanner):
    """Inspects ZIP metadata without extracting anything to disk.

    Nested ZIPs are read into memory under strict limits (file count, total size,
    depth, read budget), so a zip bomb cannot exhaust resources.
    """

    name = "archive"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.detected_mime != ZIP_MIME:
            return []
        findings: dict[str, Finding] = {}
        state = _State(read_budget=ctx.max_extracted_size)
        try:
            with zipfile.ZipFile(ctx.path) as zf:
                self._inspect(zf, 0, ctx, state, findings)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
            self._add(findings, "ARCHIVE_CORRUPT", Severity.MEDIUM,
                      "Archive could not be parsed (corrupt or unsupported)", None, 0.6)
        return list(findings.values())

    def _add(self, findings: dict[str, Finding], rule: str, severity: Severity,
             description: str, evidence: str | None, confidence: float) -> None:
        findings.setdefault(rule, Finding(self.name, rule, severity, description, evidence, confidence))

    def _inspect(self, zf: zipfile.ZipFile, depth: int, ctx: ScanContext, state: _State,
                 findings: dict[str, Finding]) -> None:
        infos = zf.infolist()
        state.files += len(infos)
        if state.files > ctx.max_archive_files:
            self._add(findings, "ARCHIVE_TOO_MANY_FILES", Severity.HIGH,
                      f"Archive contains more than the allowed {ctx.max_archive_files} entries",
                      f"entries_seen={state.files}", 0.9)
            state.stop = True
            return

        state.declared_total += sum(i.file_size for i in infos)
        if state.declared_total > ctx.max_extracted_size:
            self._add(findings, "ARCHIVE_TOO_LARGE", Severity.HIGH,
                      "Declared uncompressed size exceeds the configured limit",
                      f"declared_bytes={state.declared_total}; limit={ctx.max_extracted_size}", 0.9)
            state.stop = True
            return

        dangerous: list[str] = []
        traversal: list[str] = []
        for info in infos:
            name = info.filename
            if info.flag_bits & 0x1:
                self._add(findings, "ARCHIVE_ENCRYPTED", Severity.MEDIUM,
                          "Archive contains encrypted entries that cannot be inspected",
                          safe_evidence(name), 0.7)
            parts = name.replace("\\", "/").split("/")
            if name.startswith(("/", "\\")) or ".." in parts or (len(name) > 1 and name[1] == ":"):
                traversal.append(name)
            if not info.is_dir() and extension_of(name) in DANGEROUS_EXTENSIONS:
                dangerous.append(name)
            if (not info.is_dir() and info.file_size > MIN_SIZE_FOR_RATIO_CHECK
                    and (info.compress_size == 0
                         or info.file_size / info.compress_size > MAX_COMPRESSION_RATIO)):
                self._add(findings, "ZIP_BOMB_SUSPECTED", Severity.CRITICAL,
                          "Extremely high compression ratio, typical for zip bombs",
                          safe_evidence(f"entry={name}; size={info.file_size}; "
                                        f"compressed={info.compress_size}"), 0.85)
                state.stop = True

        if traversal:
            self._add(findings, "ARCHIVE_PATH_TRAVERSAL", Severity.HIGH,
                      "Archive entries use absolute paths or '..' (zip-slip)",
                      self._names(traversal), 0.9)
        if dangerous:
            has_exec = any(extension_of(n) in EXECUTABLE_EXTENSIONS for n in dangerous)
            self._add(findings, "ARCHIVE_DANGEROUS_ENTRY",
                      Severity.HIGH if has_exec else Severity.MEDIUM,
                      f"Archive contains {len(dangerous)} entr{'y' if len(dangerous) == 1 else 'ies'}"
                      " with dangerous extensions", self._names(dangerous), 0.8)
        if state.stop:
            return

        for info in infos:
            if info.is_dir() or extension_of(info.filename) != "zip" or info.flag_bits & 0x1:
                continue
            if depth + 1 > ctx.max_archive_depth:
                self._add(findings, "ARCHIVE_DEPTH_EXCEEDED", Severity.HIGH,
                          f"Nested archives exceed the allowed depth of {ctx.max_archive_depth}",
                          safe_evidence(info.filename), 0.9)
                state.stop = True
                return
            cap = min(MAX_NESTED_ARCHIVE_BYTES, state.read_budget)
            if info.file_size > cap:
                self._add(findings, "ARCHIVE_NESTED_NOT_INSPECTED", Severity.LOW,
                          "A nested archive is too large to inspect", safe_evidence(info.filename), 0.5)
                continue
            with zf.open(info) as member:
                data = member.read(cap + 1)
            state.read_budget -= len(data)
            if len(data) > cap or state.read_budget < 0:
                self._add(findings, "ZIP_BOMB_SUSPECTED", Severity.CRITICAL,
                          "Nested archive expands beyond its declared size",
                          safe_evidence(info.filename), 0.85)
                state.stop = True
                return
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as nested:
                    self._inspect(nested, depth + 1, ctx, state, findings)
            except zipfile.BadZipFile:
                continue
            if state.stop:
                return

    @staticmethod
    def _names(names: list[str]) -> str:
        shown = ", ".join(safe_evidence(n, 60) for n in names[:MAX_NAMES_LISTED])
        extra = len(names) - MAX_NAMES_LISTED
        return f"entries: {shown}" + (f" (+{extra} more)" if extra > 0 else "")
