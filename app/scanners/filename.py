import re
import unicodedata

from app.db.models import Severity
from app.scanners.base import BaseScanner, Finding, ScanContext, safe_evidence
from app.utils.filetype import EXTENSION_FAMILIES, extension_of, mime_family

# Executable-class extensions: running the file runs native code / installs software.
EXECUTABLE_EXTENSIONS = frozenset({"exe", "dll", "scr", "msi", "com", "pif", "cpl", "sys"})
# Script / launcher extensions: dangerous when opened, but also common in legitimate use.
SCRIPT_EXTENSIONS = frozenset({
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "jar", "lnk", "reg", "sh", "msc",
})
DANGEROUS_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS

# Extensions users expect to be harmless; combined with a dangerous last extension
# this is the classic "report.pdf.exe" trick.
DOCUMENT_LIKE_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg",
    "png", "gif", "zip", "mp3", "mp4", "odt", "html", "htm",
})

SUSPICIOUS_STEMS = frozenset({
    "invoice", "update", "payment", "document", "setup", "install", "installer", "receipt",
    "scan", "order", "statement", "resume", "cv", "photo", "image", "report", "security",
})

_TRAILING_SPACES_BEFORE_EXT = re.compile(r"[  ]{3,}\.?[A-Za-z0-9]{1,5}$")
_TRAILING_DOTS = re.compile(r"\.[A-Za-z0-9]{1,5}[. ]+$")


def _split_extensions(name: str) -> list[str]:
    return [p.strip().lower() for p in name.split(".")[1:]] if "." in name.strip(".") else []


class FilenameScanner(BaseScanner):
    name = "filename"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        name = ctx.original_filename
        findings: list[Finding] = []
        evidence = safe_evidence(name)
        exts = _split_extensions(name)
        last_ext = extension_of(name)

        if last_ext in DANGEROUS_EXTENSIONS:
            is_exec = last_ext in EXECUTABLE_EXTENSIONS
            findings.append(Finding(
                self.name, "DANGEROUS_EXTENSION",
                Severity.HIGH if is_exec else Severity.MEDIUM,
                f"File has a potentially dangerous extension (.{last_ext})",
                evidence, 0.9 if is_exec else 0.7,
            ))

            if len(exts) >= 2 and exts[-2] in DOCUMENT_LIKE_EXTENSIONS:
                findings.append(Finding(
                    self.name, "DOUBLE_EXTENSION", Severity.HIGH,
                    f"Double extension disguises a .{last_ext} file as .{exts[-2]}",
                    evidence, 0.95,
                ))

            stem = re.sub(r"[\d_\-\s()]+", "", name.rsplit(".", 1)[0].lower())
            if stem in SUSPICIOUS_STEMS:
                findings.append(Finding(
                    self.name, "SUSPICIOUS_NAME", Severity.MEDIUM,
                    f"Generic, social-engineering style name ('{stem}') on a .{last_ext} file",
                    evidence, 0.5,
                ))

        hidden_reasons = []
        if any(unicodedata.category(ch) == "Cf" for ch in name):
            hidden_reasons.append("invisible/bidirectional formatting characters")
        if _TRAILING_SPACES_BEFORE_EXT.search(name):
            hidden_reasons.append("long run of spaces before the extension")
        if _TRAILING_DOTS.search(name):
            hidden_reasons.append("trailing dots or spaces after the extension")
        if hidden_reasons:
            findings.append(Finding(
                self.name, "HIDDEN_EXTENSION", Severity.HIGH,
                "Filename may hide its real extension: " + "; ".join(hidden_reasons),
                evidence, 0.9,
            ))

        declared = (ctx.declared_mime or "").strip().lower()
        expected = EXTENSION_FAMILIES.get(last_ext)
        if declared and declared != "application/octet-stream" and expected:
            if mime_family(declared) != expected:
                findings.append(Finding(
                    self.name, "DECLARED_MIME_MISMATCH", Severity.LOW,
                    f"Client-declared type '{safe_evidence(declared, 80)}' does not match "
                    f"extension .{last_ext}",
                    evidence, 0.5,
                ))
        return findings
