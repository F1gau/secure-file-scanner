import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends
from sqlalchemy import select, update

from app.api.deps import require_role
from app.core.config import get_settings
from app.db.models import AuditLog, User, UserRole
from tests.conftest import PASSWORD

REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"


def make_token(sub=None, *, secret=None, alg="HS256", exp_delta=timedelta(minutes=5),
               include_sub=True, include_exp=True):
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"iat": now}
    if include_exp:
        payload["exp"] = now + exp_delta
    if include_sub:
        payload["sub"] = str(sub or uuid.uuid4())
    key = secret if secret is not None else settings.JWT_SECRET
    return jwt.encode(payload, None if alg == "none" else key, algorithm=alg)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------- registration ----------

async def test_register_success(client):
    r = await client.post(REGISTER, json={"email": "new@example.com", "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "email", "role", "is_active", "created_at"}
    assert body["email"] == "new@example.com"
    assert body["role"] == "USER"
    assert body["is_active"] is True


async def test_register_response_has_no_password_data(client):
    r = await client.post(REGISTER, json={"email": "new@example.com", "password": PASSWORD})
    assert PASSWORD not in r.text
    assert "hash" not in r.text.lower()
    assert "password" not in r.text.lower()


async def test_register_normalizes_email(client):
    r = await client.post(REGISTER, json={"email": "MiXed@Example.COM", "password": PASSWORD})
    assert r.status_code == 201
    assert r.json()["email"] == "mixed@example.com"


async def test_register_duplicate_email_conflict(client):
    payload = {"email": "dup@example.com", "password": PASSWORD}
    assert (await client.post(REGISTER, json=payload)).status_code == 201
    r = await client.post(REGISTER, json=payload)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CONFLICT"


async def test_register_duplicate_email_is_case_insensitive(client):
    await client.post(REGISTER, json={"email": "dup@example.com", "password": PASSWORD})
    r = await client.post(REGISTER, json={"email": "DUP@example.com", "password": PASSWORD})
    assert r.status_code == 409


async def test_register_invalid_email(client):
    r = await client.post(REGISTER, json={"email": "not-an-email", "password": PASSWORD})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_register_short_password_rejected_and_not_echoed(client):
    r = await client.post(REGISTER, json={"email": "a@example.com", "password": "pw-xyz9"})
    assert r.status_code == 422
    assert "pw-xyz9" not in r.text


async def test_register_password_over_72_bytes_rejected(client):
    r = await client.post(REGISTER, json={"email": "a@example.com", "password": "a" * 73})
    assert r.status_code == 422


async def test_register_multibyte_password_over_72_bytes_rejected(client):
    # 40 characters but 80 bytes in UTF-8
    r = await client.post(REGISTER, json={"email": "a@example.com", "password": "ы" * 40})
    assert r.status_code == 422


async def test_register_cannot_choose_role(client):
    r = await client.post(
        REGISTER, json={"email": "a@example.com", "password": PASSWORD, "role": "ADMIN"}
    )
    assert r.status_code == 422


async def test_register_missing_fields(client):
    assert (await client.post(REGISTER, json={})).status_code == 422
    assert (await client.post(REGISTER, json={"email": "a@example.com"})).status_code == 422


async def test_password_is_stored_hashed(client, session_factory):
    await client.post(REGISTER, json={"email": "h@example.com", "password": PASSWORD})
    async with session_factory() as s:
        user = (await s.execute(select(User))).scalar_one()
    assert user.hashed_password != PASSWORD
    assert PASSWORD not in user.hashed_password
    assert user.hashed_password.startswith("$2")


# ---------- login ----------

async def test_login_success_returns_working_token(client, create_user):
    await create_user()
    r = await client.post(LOGIN, json={"email": "user@example.com", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == get_settings().ACCESS_TOKEN_EXPIRE_MINUTES * 60
    me = await client.get(ME, headers=bearer(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "user@example.com"


async def test_login_email_case_insensitive(client, create_user):
    await create_user()
    r = await client.post(LOGIN, json={"email": "USER@Example.com", "password": PASSWORD})
    assert r.status_code == 200


async def test_login_wrong_password(client, create_user):
    await create_user()
    r = await client.post(LOGIN, json={"email": "user@example.com", "password": "wrong-password-1"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"
    assert r.headers["WWW-Authenticate"] == "Bearer"


async def test_login_unknown_email_same_response_as_wrong_password(client, create_user):
    await create_user()
    wrong_pw = await client.post(LOGIN, json={"email": "user@example.com", "password": "nope-nope-nope"})
    unknown = await client.post(LOGIN, json={"email": "ghost@example.com", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


async def test_login_inactive_user_rejected(client, create_user, session_factory):
    user = await create_user()
    async with session_factory() as s:
        await s.execute(update(User).where(User.id == user.id).values(is_active=False))
        await s.commit()
    r = await client.post(LOGIN, json={"email": "user@example.com", "password": PASSWORD})
    assert r.status_code == 401


async def test_login_extra_fields_rejected(client, create_user):
    await create_user()
    r = await client.post(
        LOGIN, json={"email": "user@example.com", "password": PASSWORD, "role": "ADMIN"}
    )
    assert r.status_code == 422


async def test_login_rate_limited_after_limit(client, create_user):
    await create_user()
    limit = get_settings().RATE_LIMIT_LOGIN
    bad = {"email": "user@example.com", "password": "wrong-password-1"}
    for _ in range(limit):
        assert (await client.post(LOGIN, json=bad)).status_code == 401
    r = await client.post(LOGIN, json=bad)
    assert r.status_code == 429
    assert r.json()["error"]["code"] == "RATE_LIMITED"
    assert int(r.headers["Retry-After"]) >= 1


async def test_login_rate_limit_also_blocks_correct_password(client, create_user):
    await create_user()
    limit = get_settings().RATE_LIMIT_LOGIN
    for _ in range(limit):
        await client.post(LOGIN, json={"email": "user@example.com", "password": "wrong-password-1"})
    r = await client.post(LOGIN, json={"email": "user@example.com", "password": PASSWORD})
    assert r.status_code == 429


# ---------- /me and JWT ----------

async def test_me_without_token(client):
    r = await client.get(ME)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"
    assert r.headers["WWW-Authenticate"] == "Bearer"


async def test_me_malformed_token(client):
    assert (await client.get(ME, headers=bearer("not.a.jwt"))).status_code == 401


async def test_me_wrong_scheme(client, create_user):
    user = await create_user()
    r = await client.get(ME, headers={"Authorization": f"Basic {make_token(user.id)}"})
    assert r.status_code == 401


async def test_me_expired_token(client, create_user):
    user = await create_user()
    token = make_token(user.id, exp_delta=timedelta(minutes=-1))
    assert (await client.get(ME, headers=bearer(token))).status_code == 401


async def test_me_token_signed_with_other_secret(client, create_user):
    user = await create_user()
    token = make_token(user.id, secret="a-completely-different-secret-value-123")
    assert (await client.get(ME, headers=bearer(token))).status_code == 401


async def test_me_token_with_alg_none_rejected(client, create_user):
    user = await create_user()
    token = make_token(user.id, alg="none")
    assert (await client.get(ME, headers=bearer(token))).status_code == 401


async def test_me_token_without_subject_rejected(client):
    assert (await client.get(ME, headers=bearer(make_token(include_sub=False)))).status_code == 401


async def test_me_token_without_expiry_rejected(client, create_user):
    user = await create_user()
    token = make_token(user.id, include_exp=False)
    assert (await client.get(ME, headers=bearer(token))).status_code == 401


async def test_me_token_with_non_uuid_subject_rejected(client):
    token = make_token("not-a-uuid")
    assert (await client.get(ME, headers=bearer(token))).status_code == 401


async def test_me_token_for_unknown_user_rejected(client):
    assert (await client.get(ME, headers=bearer(make_token()))).status_code == 401


async def test_me_token_for_deactivated_user_rejected(client, create_user, session_factory, auth_headers):
    user = await create_user()
    headers = await auth_headers()
    async with session_factory() as s:
        await s.execute(update(User).where(User.id == user.id).values(is_active=False))
        await s.commit()
    assert (await client.get(ME, headers=headers)).status_code == 401


async def test_me_response_has_no_password_data(client, create_user, auth_headers):
    await create_user()
    r = await client.get(ME, headers=await auth_headers())
    assert "password" not in r.text.lower()
    assert "hash" not in r.text.lower()


# ---------- RBAC ----------

def _add_admin_route(app):
    @app.get("/_admin-only")
    async def admin_only(user: User = Depends(require_role(UserRole.ADMIN))):
        return {"email": user.email}


async def test_rbac_anonymous_gets_401(app, client):
    _add_admin_route(app)
    assert (await client.get("/_admin-only")).status_code == 401


async def test_rbac_user_gets_403(app, client, create_user, auth_headers):
    _add_admin_route(app)
    await create_user()
    r = await client.get("/_admin-only", headers=await auth_headers())
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


async def test_rbac_admin_allowed(app, client, create_user, auth_headers):
    _add_admin_route(app)
    await create_user("root@example.com", role=UserRole.ADMIN)
    r = await client.get("/_admin-only", headers=await auth_headers("root@example.com"))
    assert r.status_code == 200
    assert r.json() == {"email": "root@example.com"}


async def test_rbac_uses_db_role_not_token_claims(app, client, create_user):
    """A forged 'role' claim in a validly signed token must not grant access."""
    _add_admin_route(app)
    user = await create_user()
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user.id), "iat": now, "exp": now + timedelta(minutes=5), "role": "ADMIN"},
        get_settings().JWT_SECRET, algorithm="HS256",
    )
    assert (await client.get("/_admin-only", headers=bearer(token))).status_code == 403


async def test_rbac_role_change_takes_effect_immediately(app, client, create_user, session_factory, auth_headers):
    _add_admin_route(app)
    user = await create_user()
    headers = await auth_headers()
    assert (await client.get("/_admin-only", headers=headers)).status_code == 403
    async with session_factory() as s:
        await s.execute(update(User).where(User.id == user.id).values(role="ADMIN"))
        await s.commit()
    assert (await client.get("/_admin-only", headers=headers)).status_code == 200


# ---------- audit trail of auth events ----------

async def _actions(session_factory):
    async with session_factory() as s:
        rows = (await s.execute(select(AuditLog).order_by(AuditLog.created_at))).scalars().all()
    return rows


async def test_register_writes_audit_entry(client, session_factory):
    await client.post(REGISTER, json={"email": "a@example.com", "password": PASSWORD})
    rows = await _actions(session_factory)
    assert [r.action for r in rows] == ["USER_REGISTERED"]
    assert rows[0].user_id is not None


async def test_login_success_writes_audit_entry(client, create_user, session_factory):
    await create_user()
    await client.post(LOGIN, json={"email": "user@example.com", "password": PASSWORD})
    rows = await _actions(session_factory)
    assert [r.action for r in rows] == ["USER_LOGIN"]


async def test_failed_login_writes_audit_entry_without_secrets(client, create_user, session_factory):
    user = await create_user()
    bad_password = "wrong-password-1"
    await client.post(LOGIN, json={"email": "user@example.com", "password": bad_password})
    rows = await _actions(session_factory)
    assert [r.action for r in rows] == ["LOGIN_FAILED"]
    assert rows[0].user_id == user.id
    assert bad_password not in str(rows[0].details)
    assert PASSWORD not in str(rows[0].details)


async def test_failed_login_unknown_email_has_no_user_id(client, session_factory):
    await client.post(LOGIN, json={"email": "ghost@example.com", "password": "wrong-password-1"})
    rows = await _actions(session_factory)
    assert rows[0].action == "LOGIN_FAILED"
    assert rows[0].user_id is None


async def test_audit_entries_store_request_id(client, session_factory):
    await client.post(
        REGISTER, json={"email": "a@example.com", "password": PASSWORD},
        headers={"X-Request-ID": "audit-req-0001"},
    )
    rows = await _actions(session_factory)
    assert rows[0].request_id == "audit-req-0001"
