import uuid

import pytest
from sqlalchemy import select

from app.db.models import AuditLog, File, Finding, Scan, ScanStatus
from app.scanners import BaseScanner
from app.services import scan_service
from tests import helpers as h

SCANS = "/api/v1/scans"
FILES = "/api/v1/files"
OTHER = "other@example.com"


@pytest.fixture
async def owner(create_user, auth_headers):
    await create_user()
    return await auth_headers()


async def start_scan(client, upload, headers, content, name, ctype="application/octet-stream"):
    file_id = (await upload(headers, content, name, ctype)).json()["id"]
    r = await client.post(SCANS, headers=headers, json={"file_id": file_id})
    assert r.status_code == 202, r.text
    return file_id, r.json()


async def test_create_scan_is_queued_and_dispatched(client, upload, owner, queued_scans):
    file_id, scan = await start_scan(client, upload, owner, b"hello", "a.txt", "text/plain")
    assert scan["status"] == "QUEUED" and scan["file_id"] == file_id
    assert scan["risk_score"] is None and scan["finished_at"] is None
    assert queued_scans == [uuid.UUID(scan["id"])]


async def test_create_scan_requires_auth(client):
    r = await client.post(SCANS, json={"file_id": str(uuid.uuid4())})
    assert r.status_code == 401


async def test_create_scan_unknown_file_404(client, owner):
    r = await client.post(SCANS, headers=owner, json={"file_id": str(uuid.uuid4())})
    assert r.status_code == 404


async def test_create_scan_rejects_extra_fields_and_bad_ids(client, owner):
    assert (await client.post(SCANS, headers=owner, json={"file_id": "nope"})).status_code == 422
    r = await client.post(SCANS, headers=owner, json={"file_id": str(uuid.uuid4()), "status": "COMPLETED"})
    assert r.status_code == 422


async def test_second_active_scan_for_same_file_conflicts(client, upload, owner):
    file_id, _ = await start_scan(client, upload, owner, b"hello", "a.txt")
    r = await client.post(SCANS, headers=owner, json={"file_id": file_id})
    assert r.status_code == 409


async def test_full_lifecycle_queued_running_completed(client, upload, owner, run_scan, session_factory):
    _, scan = await start_scan(client, upload, owner, b"just text\n", "notes.txt", "text/plain")
    assert (await client.get(f"{SCANS}/{scan['id']}", headers=owner)).json()["status"] == "QUEUED"

    assert await run_scan(scan["id"]) == ScanStatus.COMPLETED
    done = (await client.get(f"{SCANS}/{scan['id']}", headers=owner)).json()
    assert done["status"] == "COMPLETED" and done["risk_score"] == 0 and done["risk_level"] == "LOW"
    assert done["started_at"] and done["finished_at"] and done["error_message"] is None


async def test_scan_records_start_time_and_calls_every_scanner(client, upload, owner, session_factory,
                                                              storage):
    _, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    calls = []

    class Probe(BaseScanner):
        name = "probe"

        def scan(self, ctx):
            calls.append(ctx.original_filename)
            return []

    await scan_service.execute_scan(session_factory, storage, uuid.UUID(scan["id"]), [Probe()])
    async with session_factory() as s:
        row = await s.get(Scan, uuid.UUID(scan["id"]))
    assert calls == ["a.txt"]
    assert row.status == "COMPLETED" and row.started_at is not None and row.finished_at >= row.started_at


async def test_dangerous_file_gets_critical_findings(client, upload, owner, run_scan):
    _, scan = await start_scan(client, upload, owner, h.PE_BYTES, "report.pdf.exe", "application/pdf")
    await run_scan(scan["id"])
    done = (await client.get(f"{SCANS}/{scan['id']}", headers=owner)).json()
    assert done["status"] == "COMPLETED" and done["risk_level"] == "CRITICAL" and done["risk_score"] >= 80
    findings = (await client.get(f"{SCANS}/{scan['id']}/findings", headers=owner)).json()
    assert {"DOUBLE_EXTENSION", "DANGEROUS_EXTENSION"} <= {f["rule"] for f in findings}


async def test_findings_sorted_most_severe_first(client, upload, owner, run_scan):
    # HIGH (dangerous ext) + MEDIUM (suspicious name) + LOW (declared MIME mismatch)
    _, scan = await start_scan(client, upload, owner, h.PE_BYTES, "invoice.exe", "application/pdf")
    await run_scan(scan["id"])
    findings = (await client.get(f"{SCANS}/{scan['id']}/findings", headers=owner)).json()
    assert [f["severity"] for f in findings] == ["HIGH", "MEDIUM", "LOW"]


async def test_file_status_and_risk_reflect_latest_scan(client, upload, owner, run_scan):
    file_id, scan = await start_scan(client, upload, owner, h.PE_BYTES, "x.pdf.exe")
    assert (await client.get(f"{FILES}/{file_id}", headers=owner)).json()["status"] == "QUEUED"
    await run_scan(scan["id"])
    body = (await client.get(f"{FILES}/{file_id}", headers=owner)).json()
    assert body["status"] == "COMPLETED" and body["risk_level"] == "CRITICAL"


async def test_secret_in_file_is_masked_everywhere(client, upload, owner, run_scan, session_factory):
    content = f"STRIPE={h.FAKE_STRIPE_LIVE}\nDB_PASSWORD=FAKE_PASSWORD_VALUE\n".encode()
    _, scan = await start_scan(client, upload, owner, content, "config.env", "text/plain")
    await run_scan(scan["id"])
    findings = (await client.get(f"{SCANS}/{scan['id']}/findings", headers=owner)).json()
    assert {"STRIPE_LIVE_KEY", "PASSWORD_ASSIGNMENT"} <= {f["rule"] for f in findings}
    async with session_factory() as s:
        stored = [(f.description, f.evidence) for f in (await s.execute(select(Finding))).scalars()]
        audit = [str(r.details) for r in (await s.execute(select(AuditLog))).scalars()]
    blob = str(findings) + str(stored) + "".join(audit)
    assert h.FAKE_STRIPE_LIVE not in blob and "FAKE_PASSWORD_VALUE" not in blob


async def test_pii_file_is_flagged_as_potential_pii(client, upload, owner, run_scan):
    _, scan = await start_scan(client, upload, owner, b"Contact: ivan@example.org\n", "c.txt", "text/plain")
    await run_scan(scan["id"])
    findings = (await client.get(f"{SCANS}/{scan['id']}/findings", headers=owner)).json()
    assert findings[0]["rule"] == "PII_EMAIL" and "Potential PII" in findings[0]["description"]


async def test_zip_bomb_ends_as_rejected(client, upload, owner, run_scan):
    bomb = h.make_zip({"zeros.bin": b"\x00" * (3 * 1024 * 1024)})
    _, scan = await start_scan(client, upload, owner, bomb, "a.zip", "application/zip")
    assert await run_scan(scan["id"]) == ScanStatus.REJECTED
    done = (await client.get(f"{SCANS}/{scan['id']}", headers=owner)).json()
    assert done["status"] == "REJECTED" and done["risk_level"] in ("HIGH", "CRITICAL")


async def test_archive_over_file_limit_is_rejected(client, upload, owner, run_scan, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("MAX_ARCHIVE_FILES", "5")
    get_settings.cache_clear()
    try:
        archive = h.make_zip({f"f{i}.txt": b"x" for i in range(10)})
        _, scan = await start_scan(client, upload, owner, archive, "many.zip", "application/zip")
        assert await run_scan(scan["id"]) == ScanStatus.REJECTED
    finally:
        monkeypatch.delenv("MAX_ARCHIVE_FILES")
        get_settings.cache_clear()


async def test_scanner_crash_marks_scan_failed_with_safe_message(client, upload, owner, session_factory,
                                                                storage):
    class Boom(BaseScanner):
        name = "boom"

        def scan(self, ctx):
            raise RuntimeError("secret internal path /srv/app/x.py line 42")

    _, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    status = await scan_service.execute_scan(session_factory, storage, uuid.UUID(scan["id"]), [Boom()])
    assert status == ScanStatus.FAILED
    r = await client.get(f"{SCANS}/{scan['id']}", headers=owner)
    body = r.json()
    assert body["status"] == "FAILED" and body["error_message"] == "Scanner 'boom' failed"
    assert "secret internal path" not in r.text and "Traceback" not in r.text
    async with session_factory() as s:
        actions = [a.action for a in (await s.execute(select(AuditLog))).scalars()]
    assert "SCAN_FAILED" in actions


async def test_missing_stored_file_marks_scan_failed(client, upload, owner, run_scan, storage):
    _, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    for p in storage.root.iterdir():
        p.unlink()
    assert await run_scan(scan["id"]) == ScanStatus.FAILED
    body = (await client.get(f"{SCANS}/{scan['id']}", headers=owner)).json()
    assert body["error_message"] == "Stored file is not available"


async def test_queue_failure_returns_503_and_marks_scan_failed(client, upload, owner, monkeypatch,
                                                              session_factory):
    from app.workers import scan_tasks

    def broken(_):
        raise ConnectionError("redis://user:pw@broker down")

    monkeypatch.setattr(scan_tasks, "dispatch_scan", broken)
    file_id = (await upload(owner, b"x", "a.txt")).json()["id"]
    r = await client.post(SCANS, headers=owner, json={"file_id": file_id})
    assert r.status_code == 503 and r.json()["error"]["code"] == "QUEUE_UNAVAILABLE"
    assert "redis://" not in r.text
    async with session_factory() as s:
        assert (await s.execute(select(Scan))).scalar_one().status == "FAILED"
    # the user can retry once the queue is back
    monkeypatch.setattr(scan_tasks, "dispatch_scan", lambda _: None)
    assert (await client.post(SCANS, headers=owner, json={"file_id": file_id})).status_code == 202


async def test_executing_a_scan_twice_runs_it_once(client, upload, owner, run_scan, session_factory):
    _, scan = await start_scan(client, upload, owner, b"a@example.com", "a.txt", "text/plain")
    assert await run_scan(scan["id"]) == ScanStatus.COMPLETED
    assert await run_scan(scan["id"]) is None
    async with session_factory() as s:
        assert len((await s.execute(select(Finding))).scalars().all()) == 1


async def test_unknown_scan_id_is_ignored_by_worker(run_scan):
    assert await run_scan(uuid.uuid4()) is None


async def test_file_deleted_while_queued_is_handled(client, upload, owner, run_scan, session_factory):
    file_id, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    async with session_factory() as s:  # simulate the file disappearing while the scan is queued
        await s.delete(await s.get(File, uuid.UUID(file_id)))
        await s.commit()
    assert await run_scan(scan["id"]) is None


async def test_rescan_after_completion_creates_new_scan(client, upload, owner, run_scan):
    file_id, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    await run_scan(scan["id"])
    again = await client.post(SCANS, headers=owner, json={"file_id": file_id})
    assert again.status_code == 202 and again.json()["id"] != scan["id"]


async def test_list_scans_filter_and_isolation(client, upload, owner, run_scan, create_user, auth_headers):
    _, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    await run_scan(scan["id"])
    await start_scan(client, upload, owner, b"y", "b.txt", "text/plain")
    assert len((await client.get(SCANS, headers=owner)).json()) == 2
    done = (await client.get(SCANS, headers=owner, params={"status": "COMPLETED"})).json()
    assert [s["id"] for s in done] == [scan["id"]]
    assert (await client.get(SCANS, headers=owner, params={"status": "BOGUS"})).status_code == 422
    await create_user(OTHER)
    assert (await client.get(SCANS, headers=await auth_headers(OTHER))).json() == []


async def test_scan_lifecycle_audit_trail(client, upload, owner, run_scan, session_factory):
    _, scan = await start_scan(client, upload, owner, b"x", "a.txt", "text/plain")
    await run_scan(scan["id"])
    async with session_factory() as s:
        rows = (await s.execute(select(AuditLog).order_by(AuditLog.created_at))).scalars().all()
    actions = [r.action for r in rows]
    assert {"FILE_UPLOADED", "SCAN_CREATED", "SCAN_COMPLETED"} <= set(actions)
    completed = next(r for r in rows if r.action == "SCAN_COMPLETED")
    assert completed.details["scan_id"] == scan["id"] and completed.details["status"] == "COMPLETED"
