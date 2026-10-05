"""Shared test helpers. Every "secret" below is obviously fake and assembled at runtime,
so the repository never contains a string that looks like a real credential."""
import base64
import io
import json
import zipfile
from pathlib import Path

from app.scanners.base import ScanContext
from app.utils.filetype import detect_mime

# ---- fake credentials (built from parts) ----
FAKE_STRIPE_LIVE = "sk_" + "live_" + "FAKEFAKEFAKE1234TESTONLY"
FAKE_STRIPE_TEST = "sk_" + "test_" + "FAKEFAKEFAKE1234TESTONLY"
FAKE_AWS_KEY = "AKIA" + "FAKEFAKEFAKE1234"
FAKE_GITHUB_TOKEN = "gh" + "p_" + "FAKE" * 10
FAKE_OPENAI_KEY = "sk-" + "FAKEFAKEFAKEFAKEFAKE1234"
PRIVATE_KEY_MARKER = "-----BEGIN " + "RSA PRIVATE KEY-----"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


FAKE_JWT = ".".join([_b64({"alg": "HS256", "typ": "JWT"}), _b64({"sub": "fake-user-0001"}),
                     "FAKESIGNATUREFAKE1234"])

# ---- binary fixtures (headers only; harmless) ----
PE_BYTES = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50 + b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 200
ELF_BYTES = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 32
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32
PDF_BYTES = b"%PDF-1.4\n%fake test document\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


def make_zip(entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_ctx(tmp_path: Path, filename: str, content: bytes, declared: str | None = None,
             detected: str | None = None, **limits) -> ScanContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(content)
    return ScanContext(
        path=path, original_filename=filename, declared_mime=declared,
        detected_mime=detected or detect_mime(path), size_bytes=len(content), **limits,
    )


def rules(findings) -> set[str]:
    return {f.rule for f in findings}


def by_rule(findings, rule):
    return next(f for f in findings if f.rule == rule)
