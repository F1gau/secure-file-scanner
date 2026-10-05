"""Static file-type detection from content (magic bytes). Files are never executed or opened by an OS handler."""
import zipfile
from pathlib import Path

HEAD_SIZE = 8192

PE_MIME = "application/vnd.microsoft.portable-executable"
ELF_MIME = "application/x-elf"
MACHO_MIME = "application/x-mach-binary"
JAVA_MIME = "application/java-vm"
OLE_MIME = "application/x-ole-storage"
ZIP_MIME = "application/zip"
OCTET_MIME = "application/octet-stream"

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

EXECUTABLE_MIMES = frozenset({
    PE_MIME, ELF_MIME, MACHO_MIME, JAVA_MIME,
    "application/x-dosexec", "application/x-msdownload", "application/x-msdos-program",
    "application/x-executable", "application/x-sharedlib",
})

_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")

_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x1f\x8b", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", OLE_MIME),
]

# File extension -> expected content "family" (see mime_family()).
EXTENSION_FAMILIES: dict[str, str] = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "gif": "image/gif",
    "pdf": "application/pdf", "zip": ZIP_MIME, "gz": "application/gzip",
    "7z": "application/x-7z-compressed", "rar": "application/vnd.rar",
    "docx": DOCX, "xlsx": XLSX, "pptx": PPTX,
    "doc": OLE_MIME, "xls": OLE_MIME, "ppt": OLE_MIME, "msi": OLE_MIME,
    "exe": "executable", "dll": "executable", "scr": "executable", "com": "executable",
    "sys": "executable", "cpl": "executable", "pif": "executable",
    **{ext: "text" for ext in (
        "txt", "csv", "json", "md", "log", "xml", "html", "htm", "ini", "cfg", "conf", "yaml",
        "yml", "env", "sql", "css", "py", "js", "ps1", "bat", "cmd", "vbs", "sh", "toml", "rtf",
    )},
}

_FAMILY_ALIASES = {
    "application/x-zip-compressed": ZIP_MIME,
    "application/msword": OLE_MIME,
    "application/vnd.ms-excel": OLE_MIME,
    "application/vnd.ms-powerpoint": OLE_MIME,
    "application/x-gzip": "application/gzip",
    "image/jpg": "image/jpeg",
    "application/x-rar-compressed": "application/vnd.rar",
    "application/json": "text",
    "application/xml": "text",
    "application/javascript": "text",
    "application/x-sh": "text",
}


def is_executable_mime(mime: str) -> bool:
    return mime in EXECUTABLE_MIMES


def is_text_mime(mime: str) -> bool:
    return mime.startswith("text/")


def mime_family(mime: str) -> str:
    """Collapse equivalent MIME types: all text/* -> "text", executables -> "executable"."""
    mime = mime.lower().split(";")[0].strip()
    if is_text_mime(mime):
        return "text"
    if is_executable_mime(mime):
        return "executable"
    return _FAMILY_ALIASES.get(mime, mime)


def extension_of(filename: str) -> str:
    name = filename.strip().rstrip(". ")
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _is_pe(head: bytes) -> bool:
    if not head.startswith(b"MZ"):
        return False
    if len(head) >= 0x40:
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < offset <= len(head) - 4 and head[offset:offset + 4] == b"PE\x00\x00":
            return True
    if b"This program cannot be run in DOS mode" in head:
        return True
    return b"\x00" in head[:64]  # heuristic: MZ followed by binary data


def _looks_like_text(head: bytes) -> bool:
    if not head or head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head:
        return False
    bad = sum(1 for b in head if b < 9 or (13 < b < 32 and b != 27))
    return bad / len(head) < 0.02


def _refine_zip(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return ZIP_MIME
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return DOCX
        if any(n.startswith("xl/") for n in names):
            return XLSX
        if any(n.startswith("ppt/") for n in names):
            return PPTX
    if "META-INF/MANIFEST.MF" in names:
        return "application/java-archive"
    return ZIP_MIME


def detect_mime(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(HEAD_SIZE)

    if _is_pe(head):
        return PE_MIME
    if head.startswith(b"\x7fELF"):
        return ELF_MIME
    if head[:4] in _MACHO_MAGICS:
        return MACHO_MIME
    if head.startswith(b"\xca\xfe\xba\xbe"):
        return JAVA_MIME
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _refine_zip(path)
    for magic, mime in _SIGNATURES:
        if head.startswith(magic):
            return mime
    if _looks_like_text(head):
        probe = head.lstrip().lower()
        if head.startswith(b"#!"):
            return "text/x-shellscript"
        if probe.startswith((b"<!doctype html", b"<html")):
            return "text/html"
        return "text/plain"
    return OCTET_MIME
