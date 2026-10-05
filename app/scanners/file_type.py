from app.db.models import Severity
from app.scanners.base import BaseScanner, Finding, ScanContext, safe_evidence
from app.utils.filetype import EXTENSION_FAMILIES, extension_of, is_executable_mime, mime_family


class FileTypeScanner(BaseScanner):
    """Compares the extension with the type detected from the file's actual content."""

    name = "file_type"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        ext = extension_of(ctx.original_filename)
        expected = EXTENSION_FAMILIES.get(ext)
        detected = ctx.detected_mime
        detected_family = mime_family(detected)
        evidence = safe_evidence(f"name={ctx.original_filename}; detected={detected}")

        if is_executable_mime(detected) and expected != "executable":
            return [Finding(
                self.name, "TYPE_MISMATCH", Severity.HIGH,
                f"Content looks like an executable ({detected}) but the extension is "
                f"'.{ext or 'none'}'",
                evidence, 0.95 if expected else 0.8,
            )]

        if expected and detected_family != expected:
            return [Finding(
                self.name, "TYPE_MISMATCH", Severity.MEDIUM,
                f"Extension .{ext} does not match the detected content type ({detected})",
                evidence, 0.7,
            )]
        return []
