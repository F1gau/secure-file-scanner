import pytest

from app.core.config import Settings
from app.main import normalize_request_id


async def test_health_ok(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_ready_reports_unavailable_without_redis(client):
    r = await client.get("/health/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "unavailable"
    assert body["checks"]["redis"] == "unavailable"


async def test_request_id_generated(client):
    r = await client.get("/health")
    assert len(r.headers["X-Request-ID"]) == 32


async def test_request_id_valid_client_value_kept(client):
    r = await client.get("/health", headers={"X-Request-ID": "client-req-12345"})
    assert r.headers["X-Request-ID"] == "client-req-12345"


@pytest.mark.parametrize("bad", ["short", "has space in it!", "x" * 65, "a\tb" * 5, ""])
async def test_request_id_invalid_replaced(bad):
    assert normalize_request_id(bad) != bad
    assert len(normalize_request_id(bad)) == 32


async def test_unknown_route_uses_error_format(client):
    r = await client.get("/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


async def test_unhandled_error_hides_traceback(app, client):
    @app.get("/_boom")
    async def boom():
        raise RuntimeError("secret internal detail")

    r = await client.get("/_boom")
    assert r.status_code == 500
    assert r.json() == {"error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}}
    assert "secret internal detail" not in r.text
    assert "Traceback" not in r.text


def test_production_rejects_default_jwt_secret():
    s = Settings(APP_ENV="production", JWT_SECRET="change-me-in-production")
    with pytest.raises(RuntimeError):
        s.validate_for_runtime()


def test_production_rejects_short_jwt_secret():
    s = Settings(APP_ENV="production", JWT_SECRET="short")
    with pytest.raises(RuntimeError):
        s.validate_for_runtime()


def test_production_accepts_strong_jwt_secret():
    Settings(APP_ENV="production", JWT_SECRET="x" * 40).validate_for_runtime()


def test_size_limit_conversion():
    assert Settings(MAX_FILE_SIZE_MB=10).max_file_size_bytes == 10 * 1024 * 1024
