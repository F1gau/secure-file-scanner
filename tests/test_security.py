"""The ten security checks required by the project specification (section 29), plus extras."""
import ast
import re
import uuid
from pathlib import Path

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.db.models import AuditLog, Finding
from tests import helpers as h

ROOT = Path(__file__).resolve().parent.parent
APP_DIR = ROOT / "app"
PASSWORD = "correct-horse-battery"
OTHER = "other@example.com"


# 1. A user cannot get somebody else's file (or scan, or findings, or delete it).
async def test_01_cannot_access_other_users_resources(client, create_user, auth_headers, upload, run_scan):
    await create_user()
    await create_user(OTHER)
    alice, mallory = await auth_headers(), await auth_headers(OTHER)
    file_id = (await upload(alice, b"private", "a.txt", "text/plain")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=alice, json={"file_id": file_id})).json()
    await run_scan(scan["id"])

    assert (await client.get(f"/api/v1/files/{file_id}", headers=mallory)).status_code == 404
    assert (await client.delete(f"/api/v1/files/{file_id}", headers=mallory)).status_code == 404
    assert (await client.post("/api/v1/scans", headers=mallory, json={"file_id": file_id})).status_code == 404
    assert (await client.get(f"/api/v1/scans/{scan['id']}", headers=mallory)).status_code == 404
    assert (await client.get(f"/api/v1/scans/{scan['id']}/findings", headers=mallory)).status_code == 404
    assert (await client.get("/api/v1/files", headers=mallory)).json() == []
    # the owner still has everything
    assert (await client.get(f"/api/v1/files/{file_id}", headers=alice)).status_code == 200


async def test_01b_foreign_and_missing_resources_are_indistinguishable(client, create_user, auth_headers,
                                                                      upload):
    await create_user()
    await create_user(OTHER)
    file_id = (await upload(await auth_headers(), b"x", "a.txt")).json()["id"]
    mallory = await auth_headers(OTHER)
    foreign = await client.get(f"/api/v1/files/{file_id}", headers=mallory)
    missing = await client.get(f"/api/v1/files/{uuid.uuid4()}", headers=mallory)
    assert foreign.status_code == missing.status_code == 404 and foreign.json() == missing.json()


# 2. USER cannot open ADMIN endpoints.
async def test_02_user_cannot_use_admin_endpoints(client, create_user, auth_headers):
    await create_user()
    headers = await auth_headers()
    for path in ("/api/v1/admin/users", "/api/v1/admin/scans", "/api/v1/admin/audit", "/api/v1/stats"):
        assert (await client.get(path, headers=headers)).status_code == 403


# 3. ../ cannot be used.
async def test_03_path_traversal_in_filename_is_neutralised(client, create_user, auth_headers, upload,
                                                           storage, tmp_path):
    await create_user()
    headers = await auth_headers()
    for evil in ("../../../etc/passwd", "..\\..\\boot.ini", "....//....//x", "%2e%2e/%2e%2e/x",
                 "a/../../../b.txt"):
        r = await upload(headers, b"payload", evil)
        assert r.status_code == 201
    outside = [p for p in tmp_path.rglob("*") if storage.root not in p.parents and p != storage.root
               and p.is_file()]
    assert outside == []
    assert all(re.fullmatch(r"[0-9a-f]{32}", p.name) for p in storage.root.iterdir())


async def test_03b_path_traversal_in_file_id_is_rejected(client, create_user, auth_headers):
    await create_user()
    headers = await auth_headers()
    r = await client.get("/api/v1/files/..%2F..%2Fetc%2Fpasswd", headers=headers)
    assert r.status_code in (404, 422)


# 4. A file above the limit cannot be uploaded.
async def test_04_file_above_limit_rejected(client, create_user, auth_headers, upload, monkeypatch, storage):
    await create_user()
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "1")
    get_settings.cache_clear()
    try:
        r = await upload(await auth_headers(), b"0" * (1024 * 1024 + 1), "big.bin")
    finally:
        monkeypatch.delenv("MAX_FILE_SIZE_MB")
        get_settings.cache_clear()
    assert r.status_code == 413 and list(storage.root.iterdir()) == []


# 5. An uploaded file is never executed.
async def test_05_uploaded_files_are_never_executed(client, create_user, auth_headers, upload, run_scan,
                                                    tmp_path, monkeypatch):
    import os
    import subprocess

    marker = tmp_path / "EXECUTED"
    script = f"#!/bin/sh\ntouch {marker}\n".encode()

    def forbidden(*args, **kwargs):
        raise AssertionError("process execution attempted while handling an upload")

    for name in ("system", "popen", "execv", "execve", "execl", "execvp", "spawnv", "posix_spawn"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    await create_user()
    headers = await auth_headers()
    for name, content in (("run.sh", script), ("evil.exe", h.PE_BYTES), ("m.py", b"import os\nos.system('x')\n")):
        file_id = (await upload(headers, content, name)).json()["id"]
        scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
        await run_scan(scan["id"])
    assert not marker.exists()


def test_05b_application_code_contains_no_dynamic_execution():
    """Static guard: no exec/eval/os.system/subprocess anywhere in the application package."""
    banned_calls = {"eval", "exec", "compile", "__import__"}
    banned_attrs = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
                    ("os", "spawnl"), ("os", "spawnv"), ("subprocess", "run"), ("subprocess", "Popen"),
                    ("subprocess", "call"), ("subprocess", "check_output"), ("subprocess", "check_call")}
    offences = []
    for path in APP_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "subprocess" for a in node.names):
                offences.append(f"{path.name}: import subprocess")
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in banned_calls:
                    offences.append(f"{path.name}:{node.lineno}: {fn.id}()")
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) \
                        and (fn.value.id, fn.attr) in banned_attrs:
                    offences.append(f"{path.name}:{node.lineno}: {fn.value.id}.{fn.attr}()")
    assert offences == []


# 6. A detected secret never reaches the audit log (or any stored finding / response).
async def test_06_found_secret_not_in_audit_log(client, create_user, auth_headers, upload, run_scan,
                                                session_factory):
    await create_user()
    headers = await auth_headers()
    secrets = [h.FAKE_STRIPE_LIVE, h.FAKE_AWS_KEY, h.FAKE_GITHUB_TOKEN, h.FAKE_JWT, h.FAKE_OPENAI_KEY,
               "FAKE_PASSWORD_VALUE"]
    body = "\n".join(secrets[:-1]) + "\npassword = FAKE_PASSWORD_VALUE\n" + h.PRIVATE_KEY_MARKER + "\n"
    file_id = (await upload(headers, body.encode(), "leak.txt", "text/plain")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
    await run_scan(scan["id"])
    await client.get(f"/api/v1/scans/{scan['id']}/findings", headers=headers)

    async with session_factory() as s:
        audit_blob = " ".join(f"{r.action} {r.details} {r.ip_address}"
                              for r in (await s.execute(select(AuditLog))).scalars())
        finding_blob = " ".join(f"{f.description} {f.evidence}"
                                for f in (await s.execute(select(Finding))).scalars())
    findings_response = (await client.get(f"/api/v1/scans/{scan['id']}/findings", headers=headers)).text
    for secret in secrets:
        assert secret not in audit_blob
        assert secret not in finding_blob
        assert secret not in findings_response


async def test_06b_secrets_do_not_reach_application_logs(client, create_user, auth_headers, upload, run_scan,
                                                         caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    await create_user()
    headers = await auth_headers()
    body = f"key={h.FAKE_STRIPE_LIVE}\n".encode()
    file_id = (await upload(headers, body, "leak.txt", "text/plain")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
    await run_scan(scan["id"])
    assert h.FAKE_STRIPE_LIVE not in caplog.text and PASSWORD not in caplog.text


# 7. The password never appears in a response (or logs).
async def test_07_password_not_in_any_response(client, create_user, auth_headers, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    reg = await client.post("/api/v1/auth/register", json={"email": "p@example.com", "password": PASSWORD})
    login = await client.post("/api/v1/auth/login", json={"email": "p@example.com", "password": PASSWORD})
    bad = await client.post("/api/v1/auth/login", json={"email": "p@example.com", "password": "wrong-password-1"})
    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    for response in (reg, login, bad, me):
        assert PASSWORD not in response.text and "wrong-password-1" not in response.text
        assert "hashed_password" not in response.text
    assert PASSWORD not in caplog.text and "wrong-password-1" not in caplog.text


# 8. The JWT secret is not in the source code.
def test_08_jwt_secret_not_hardcoded_in_source():
    secret = get_settings().JWT_SECRET
    assert secret
    for path in list(APP_DIR.rglob("*.py")) + [ROOT / "alembic" / "env.py", ROOT / "Dockerfile",
                                               ROOT / "docker-compose.yml", ROOT / ".env.example"]:
        if path.exists():
            assert secret not in path.read_text(encoding="utf-8"), path


def test_08b_config_has_no_real_default_secret_and_env_example_is_placeholder():
    assert Settings.model_fields["JWT_SECRET"].default == "change-me-in-production"
    example = (ROOT / ".env.example").read_text()
    assert "JWT_SECRET=change-me-in-production" in example
    assert not (ROOT / ".env").exists() or ".env" in (ROOT / ".gitignore").read_text().splitlines()


def test_08c_no_credential_like_strings_in_application_source():
    pattern = re.compile(r"(AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{10,}|gh[pousr]_[A-Za-z0-9]{30,}|"
                         r"-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.eyJ)")
    for path in list(APP_DIR.rglob("*.py")) + list((ROOT / "tests").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert not pattern.search(text), f"credential-like string in {path}"


# 9. A server error does not reveal a traceback.
async def test_09_server_error_hides_traceback(app, client):
    @app.get("/_explode")
    async def explode():
        raise ValueError("db password is hunter2 at /srv/app/secret.py")

    r = await client.get("/_explode")
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}}
    for leaked in ("hunter2", "/srv/app", "Traceback", "ValueError", "File \""):
        assert leaked not in r.text


async def test_09b_validation_errors_do_not_echo_submitted_values(client):
    r = await client.post("/api/v1/auth/login", json={"email": "not-an-email-SENTINEL", "password": "x"})
    assert r.status_code == 422 and "SENTINEL" not in r.text


async def test_09c_failed_scan_exposes_no_traceback(client, create_user, auth_headers, upload,
                                                    session_factory, storage):
    from app.scanners import BaseScanner
    from app.services import scan_service

    class Boom(BaseScanner):
        name = "boom"

        def scan(self, ctx):
            raise RuntimeError("password=hunter2 /srv/app/x.py")

    await create_user()
    headers = await auth_headers()
    file_id = (await upload(headers, b"x", "a.txt")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
    await scan_service.execute_scan(session_factory, storage, uuid.UUID(scan["id"]), [Boom()])
    r = await client.get(f"/api/v1/scans/{scan['id']}", headers=headers)
    assert "hunter2" not in r.text and "Traceback" not in r.text and "/srv/app" not in r.text


# 10. An archive that exceeds the limits is rejected.
async def test_10_archive_over_limits_is_rejected(client, create_user, auth_headers, upload, run_scan):
    await create_user()
    headers = await auth_headers()
    bomb = h.make_zip({"zeros.bin": b"\x00" * (4 * 1024 * 1024)})
    file_id = (await upload(headers, bomb, "bomb.zip", "application/zip")).json()["id"]
    scan = (await client.post("/api/v1/scans", headers=headers, json={"file_id": file_id})).json()
    await run_scan(scan["id"])
    done = (await client.get(f"/api/v1/scans/{scan['id']}", headers=headers)).json()
    assert done["status"] == "REJECTED"
    rules = {f["rule"] for f in (await client.get(f"/api/v1/scans/{scan['id']}/findings", headers=headers)).json()}
    assert "ZIP_BOMB_SUSPECTED" in rules


# ---- extras ----

def test_no_wildcard_cors_or_debug_mode():
    from app.main import create_app
    app = create_app()
    assert app.debug is False
    assert not any(m.cls.__name__ == "CORSMiddleware" for m in app.user_middleware)


def test_dockerized_stack_does_not_embed_real_secrets():
    compose = (ROOT / "docker-compose.yml")
    if compose.exists():
        text = compose.read_text()
        assert "JWT_SECRET: change-me" not in text
        assert "${JWT_SECRET:?" in text  # compose refuses to start without a real secret


async def test_security_response_always_carries_request_id(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401 and len(r.headers["X-Request-ID"]) >= 8
