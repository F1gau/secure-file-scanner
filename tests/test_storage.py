import os

import pytest

from app.utils import filetype as ft
from app.utils.hashing import StreamHasher, sha256_bytes, sha256_file
from app.utils.storage import (
    FileStorage,
    StorageError,
    clean_filename,
    escape_format_chars,
    new_stored_name,
)
from tests import helpers as h

# ---------- filename cleaning ----------

@pytest.mark.parametrize("raw,expected", [
    ("report.pdf", "report.pdf"),
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\evil.exe", "evil.exe"),
    ("/etc/shadow", "shadow"),
    ("C:\\temp\\a.txt", "a.txt"),
    ("a/b/../c.txt", "c.txt"),
    ("..", "unnamed"),
    (".", "unnamed"),
    ("", "unnamed"),
    (None, "unnamed"),
    ("name\x00.txt.exe", "name.txt.exe"),
    ("  spaced.txt  ", "spaced.txt"),
    ("line\nbreak.txt", "linebreak.txt"),
])
def test_clean_filename(raw, expected):
    assert clean_filename(raw) == expected


def test_clean_filename_limits_length_and_keeps_extension():
    cleaned = clean_filename("a" * 1000 + ".exe")
    assert len(cleaned) <= 255 and cleaned.endswith(".exe")


def test_clean_filename_keeps_bidi_chars_for_scanner_and_escape_makes_them_visible():
    name = clean_filename("photo\u202egpj.exe")
    assert "\u202e" in name
    assert "\\u202e" in escape_format_chars(name)


# ---------- storage ----------

def test_stored_names_are_random_hex():
    a, b = new_stored_name(), new_stored_name()
    assert a != b and len(a) == 32 and int(a, 16) >= 0


@pytest.mark.parametrize("bad", ["../x", "..", "a/b", "/etc/passwd", "x" * 31, "G" * 32, "", "a\x00b",
                                 "0123456789abcdef0123456789abcdef/../x"])
def test_path_for_rejects_anything_but_uuid_hex(tmp_path, bad):
    with pytest.raises(StorageError):
        FileStorage(tmp_path / "s").path_for(bad)


def test_path_for_stays_inside_root(tmp_path):
    st = FileStorage(tmp_path / "s")
    name = new_stored_name()
    assert st.path_for(name).parent == st.root


def test_symlink_pointing_outside_is_rejected(tmp_path):
    st = FileStorage(tmp_path / "s")
    name = new_stored_name()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    os.symlink(outside, st.root / name)
    with pytest.raises(StorageError):
        st.path_for(name)


def test_open_new_creates_private_file_and_never_overwrites(tmp_path):
    st = FileStorage(tmp_path / "s")
    name = new_stored_name()
    with st.open_new(name) as fh:
        fh.write(b"data")
    assert oct(st.path_for(name).stat().st_mode & 0o777) == "0o600"
    with pytest.raises(FileExistsError):
        st.open_new(name)


def test_delete_and_exists(tmp_path):
    st = FileStorage(tmp_path / "s")
    name = new_stored_name()
    with st.open_new(name) as fh:
        fh.write(b"x")
    assert st.exists(name) and st.delete(name) is True
    assert not st.exists(name) and st.delete(name) is False


# ---------- hashing ----------

def test_sha256_known_vectors():
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_stream_hasher_matches_one_shot_and_counts_bytes():
    hasher = StreamHasher()
    for chunk in (b"a", b"bc", b""):
        hasher.update(chunk)
    assert hasher.hexdigest() == sha256_bytes(b"abc") and hasher.size == 3


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 200_000)
    assert sha256_file(p) == sha256_bytes(b"x" * 200_000)


# ---------- type detection ----------

@pytest.mark.parametrize("content,expected", [
    (h.PE_BYTES, ft.PE_MIME), (h.ELF_BYTES, ft.ELF_MIME),
    (b"\xcf\xfa\xed\xfe" + b"\x00" * 20, ft.MACHO_MIME),
    (b"\xca\xfe\xba\xbe" + b"\x00" * 20, ft.JAVA_MIME),
    (h.PDF_BYTES, "application/pdf"), (h.PNG_BYTES, "image/png"), (h.JPEG_BYTES, "image/jpeg"),
    (b"GIF89a" + b"\x00" * 10, "image/gif"), (b"\x1f\x8b\x08" + b"\x00" * 10, "application/gzip"),
    (h.make_zip({"a.txt": b"x"}), ft.ZIP_MIME),
    (h.make_zip({"[Content_Types].xml": b"<x/>", "word/document.xml": b"<x/>"}), ft.DOCX),
    (h.make_zip({"[Content_Types].xml": b"<x/>", "xl/workbook.xml": b"<x/>"}), ft.XLSX),
    (h.make_zip({"META-INF/MANIFEST.MF": b"x"}), "application/java-archive"),
    (b"just some text\n", "text/plain"), (b"", "text/plain"),
    (b"#!/bin/sh\necho hi\n", "text/x-shellscript"), (b"<!DOCTYPE html><html></html>", "text/html"),
    (b"\xef\xbb\xbfutf8 bom text", "text/plain"), (bytes(range(0, 32)) * 5, ft.OCTET_MIME),
])
def test_detect_mime(tmp_path, content, expected):
    p = tmp_path / "f"
    p.write_bytes(content)
    assert ft.detect_mime(p) == expected


def test_detection_ignores_filename_and_content_type(tmp_path):
    p = tmp_path / "innocent.jpg"
    p.write_bytes(h.PE_BYTES)
    assert ft.is_executable_mime(ft.detect_mime(p))


def test_mime_family_normalization():
    assert ft.mime_family("text/csv") == "text" and ft.mime_family("Application/JSON; x=1") == "text"
    assert ft.mime_family("image/jpg") == "image/jpeg"
    assert ft.mime_family(ft.PE_MIME) == "executable"
    assert ft.extension_of("a.tar.GZ") == "gz" and ft.extension_of("noext") == "" and ft.extension_of("a.exe. ") == "exe"
