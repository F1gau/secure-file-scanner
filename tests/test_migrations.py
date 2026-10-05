"""Run Alembic as a subprocess (its env.py uses asyncio.run) against a temp SQLite file."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_TABLES = {"users", "files", "scans", "findings", "audit_logs"}


def alembic(db_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{db_path}",
        "JWT_SECRET": "test-only-jwt-secret-not-for-production-use",
        "APP_ENV": "test",
    }
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )


def tables(db_path: Path) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    finally:
        con.close()
    return {r[0] for r in rows} - {"alembic_version"}


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "migration.db"


def test_upgrade_head_creates_all_tables(db_path):
    r = alembic(db_path, "upgrade", "head")
    assert r.returncode == 0, r.stderr
    assert tables(db_path) == EXPECTED_TABLES


def test_downgrade_base_removes_all_tables(db_path):
    assert alembic(db_path, "upgrade", "head").returncode == 0
    r = alembic(db_path, "downgrade", "base")
    assert r.returncode == 0, r.stderr
    assert tables(db_path) == set()


def test_models_match_migrations(db_path):
    """`alembic check` fails if models drifted from the migration history."""
    assert alembic(db_path, "upgrade", "head").returncode == 0
    r = alembic(db_path, "check")
    assert r.returncode == 0, r.stdout + r.stderr


def test_upgrade_is_idempotent(db_path):
    assert alembic(db_path, "upgrade", "head").returncode == 0
    assert alembic(db_path, "upgrade", "head").returncode == 0
