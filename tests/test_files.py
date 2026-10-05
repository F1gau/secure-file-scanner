import uuid

from sqlalchemy import select

from app.core.config import get_settings
from app.db.models import AuditLog, File
from app.utils.hashing import sha256_bytes
from tests import helpers as h

FILES = "/api/v1/files"
OTHER = "other@example.com"


async def test_upload_requires_authentication(client):
    r = await client.post(FILES, files={"file": ("a.txt", b"x", "text/plain")})
    assert r.status_code == 401


async def test_upload_success_returns_metadata_without_content(client, create_user, auth_headers, upload):
    await create_user()
    content = b"hello secure world\n"
    r = await upload(await auth_headers(), content, "hello.txt")
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "original_filename", "size_bytes", "declared_mime", "detected_mime",
                         "sha256", "created_at", "status", "risk_level"}
    assert body["original_filename"] == "hello.txt"
    assert body["size_bytes"] == len(content)
    assert body["sha256"] == sha256_bytes(content)
    assert body["detected_mime"] == "text/plain"
    assert body["status"] == "UPLOADED" and body["risk_level"] is None
    assert "hello secure world" not in r.text and "stored_name" not in r.text


async def test_sha256_matches_for_binary_upload(client, create_user, auth_headers, upload):
    await create_user()
    r = await upload(await auth_headers(), h.PNG_BYTES, "pic.png", "image/png")
    assert r.json()["sha256"] == sha256_bytes(h.PNG_BYTES)


async def test_real_type_detected_ignoring_client_content_type(client, create_user, auth_headers, upload):
    await create_user()
    r = await upload(await auth_headers(), h.PE_BYTES, "image.jpg", "image/jpeg")
    body = r.json()
    assert body["declared_mime"] == "image/jpeg"
    assert body["detected_mime"] == "application/vnd.microsoft.portable-executable"


async def test_file_stored_under_random_name_in_storage_dir(client, create_user, auth_headers, upload,
                                                            storage, session_factory):
    await create_user()
    await upload(await auth_headers(), b"abc", "../../evil.txt")
    async with session_factory() as s:
        record = (await s.execute(select(File))).scalar_one()
    assert record.original_filename == "evil.txt"
    assert record.stored_name != "evil.txt" and len(record.stored_name) == 32
    assert [p.name for p in storage.root.iterdir()] == [record.stored_name]
    assert storage.path_for(record.stored_name).read_bytes() == b"abc"


async def test_path_traversal_filename_never_escapes_storage(client, create_user, auth_headers, upload,
                                                             storage, tmp_path):
    await create_user()
    headers = await auth_headers()
    for name in ("../../../tmp/pwned.txt", "..\\..\\pwned.txt", "/etc/cron.d/pwned"):
        r = await upload(headers, b"x", name)
        assert r.status_code == 201
        assert "/" not in r.json()["original_filename"] and "\\" not in r.json()["original_filename"]
    assert not (tmp_path / "pwned.txt").exists()
    assert all(p.parent == storage.root for p in storage.root.iterdir())


async def test_empty_file_rejected_and_nothing_left_on_disk(client, create_user, auth_headers, upload, storage):
    await create_user()
    r = await upload(await auth_headers(), b"", "empty.txt")
    assert r.status_code == 400 and r.json()["error"]["code"] == "EMPTY_FILE"
    assert list(storage.root.iterdir()) == []


async def test_file_over_limit_rejected_with_413_and_cleaned_up(client, create_user, auth_headers, upload,
                                                               storage, session_factory, monkeypatch):
    await create_user()
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "1")
    get_settings.cache_clear()
    try:
        r = await upload(await auth_headers(), b"a" * (1024 * 1024 + 1), "big.txt")
    finally:
        monkeypatch.delenv("MAX_FILE_SIZE_MB")
        get_settings.cache_clear()
    assert r.status_code == 413
    assert r.json() == {"error": {"code": "FILE_TOO_LARGE", "message": "File exceeds configured size limit"}}
    assert list(storage.root.iterdir()) == []
    async with session_factory() as s:
        assert (await s.execute(select(File))).scalars().all() == []


async def test_file_exactly_at_limit_is_accepted(client, create_user, auth_headers, upload, monkeypatch):
    await create_user()
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "1")
    get_settings.cache_clear()
    try:
        r = await upload(await auth_headers(), b"a" * (1024 * 1024), "edge.txt")
    finally:
        monkeypatch.delenv("MAX_FILE_SIZE_MB")
        get_settings.cache_clear()
    assert r.status_code == 201


async def test_oversized_content_length_rejected_before_reading_body(client, create_user, auth_headers):
    await create_user()
    headers = {**await auth_headers(), "Content-Length": str(500 * 1024 * 1024),
               "Content-Type": "multipart/form-data; boundary=x"}
    r = await client.post(FILES, headers=headers, content=b"--x--")
    assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"


async def test_missing_file_field_is_422(client, create_user, auth_headers):
    await create_user()
    r = await client.post(FILES, headers=await auth_headers(), data={"x": "y"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_upload_is_audited_without_content(client, create_user, auth_headers, upload, session_factory):
    await create_user()
    await upload(await auth_headers(), b"super private text", "doc.txt")
    async with session_factory() as s:
        rows = (await s.execute(select(AuditLog).where(AuditLog.action == "FILE_UPLOADED"))).scalars().all()
    assert len(rows) == 1 and rows[0].details["filename"] == "doc.txt"
    assert "super private text" not in str(rows[0].details)


async def test_upload_rate_limited(client, create_user, auth_headers, upload):
    await create_user()
    headers = await auth_headers()
    limit = get_settings().RATE_LIMIT_UPLOAD
    for _ in range(limit):
        assert (await upload(headers, b"x")).status_code == 201
    r = await upload(headers, b"x")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


async def test_upload_rate_limit_is_per_user(client, create_user, auth_headers, upload):
    await create_user()
    await create_user(OTHER)
    limit = get_settings().RATE_LIMIT_UPLOAD
    first = await auth_headers()
    for _ in range(limit + 1):
        await upload(first, b"x")
    assert (await upload(await auth_headers(OTHER), b"x")).status_code == 201


# ---------- listing / reading ----------

async def test_get_file_metadata(client, create_user, auth_headers, upload):
    await create_user()
    headers = await auth_headers()
    file_id = (await upload(headers, b"abc", "a.txt")).json()["id"]
    r = await client.get(f"{FILES}/{file_id}", headers=headers)
    assert r.status_code == 200 and r.json()["id"] == file_id


async def test_list_returns_only_own_files_newest_first(client, create_user, auth_headers, upload):
    await create_user()
    await create_user(OTHER)
    mine, theirs = await auth_headers(), await auth_headers(OTHER)
    first = (await upload(mine, b"1", "first.txt")).json()["id"]
    second = (await upload(mine, b"2", "second.txt")).json()["id"]
    await upload(theirs, b"3", "other.txt")
    ids = [f["id"] for f in (await client.get(FILES, headers=mine)).json()]
    assert ids == [second, first]


async def test_list_pagination_and_validation(client, create_user, auth_headers, upload):
    await create_user()
    headers = await auth_headers()
    for i in range(3):
        await upload(headers, b"x", f"{i}.txt")
    assert len((await client.get(FILES, headers=headers, params={"limit": 2})).json()) == 2
    assert len((await client.get(FILES, headers=headers, params={"offset": 2})).json()) == 1
    assert (await client.get(FILES, headers=headers, params={"limit": 1000})).status_code == 422


async def test_get_unknown_file_404(client, create_user, auth_headers):
    await create_user()
    r = await client.get(f"{FILES}/{uuid.uuid4()}", headers=await auth_headers())
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


async def test_get_file_invalid_uuid_is_422(client, create_user, auth_headers):
    await create_user()
    assert (await client.get(f"{FILES}/not-a-uuid", headers=await auth_headers())).status_code == 422


async def test_filename_with_bidi_char_is_escaped_in_response(client, create_user, auth_headers, upload):
    await create_user()
    r = await upload(await auth_headers(), b"x", "photo‮gpj.exe")
    assert "‮" not in r.text and "\\u202e" in r.json()["original_filename"]


# ---------- delete ----------

async def test_delete_removes_record_and_stored_file(client, create_user, auth_headers, upload, storage):
    await create_user()
    headers = await auth_headers()
    file_id = (await upload(headers, b"abc", "a.txt")).json()["id"]
    assert (await client.delete(f"{FILES}/{file_id}", headers=headers)).status_code == 204
    assert (await client.get(f"{FILES}/{file_id}", headers=headers)).status_code == 404
    assert list(storage.root.iterdir()) == []


async def test_delete_is_audited(client, create_user, auth_headers, upload, session_factory):
    await create_user()
    headers = await auth_headers()
    file_id = (await upload(headers, b"abc", "a.txt")).json()["id"]
    await client.delete(f"{FILES}/{file_id}", headers=headers)
    async with session_factory() as s:
        actions = [r.action for r in (await s.execute(select(AuditLog))).scalars()]
    assert "FILE_DELETED" in actions


async def test_delete_unknown_file_404(client, create_user, auth_headers):
    await create_user()
    assert (await client.delete(f"{FILES}/{uuid.uuid4()}", headers=await auth_headers())).status_code == 404


async def test_delete_blocked_while_scan_is_active(client, create_user, auth_headers, upload):
    await create_user()
    headers = await auth_headers()
    file_id = (await upload(headers, b"abc", "a.txt")).json()["id"]
    await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})
    r = await client.delete(f"{FILES}/{file_id}", headers=headers)
    assert r.status_code == 409 and r.json()["error"]["code"] == "CONFLICT"
