import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.exceptions import AuthenticationError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    validate_password_strength,
    verify_password,
)


def test_hash_is_salted():
    assert hash_password("same-password-1") != hash_password("same-password-1")


def test_hash_does_not_contain_plaintext():
    assert "plain-secret-pw" not in hash_password("plain-secret-pw")


def test_verify_password_roundtrip():
    h = hash_password("right-password-1")
    assert verify_password("right-password-1", h) is True
    assert verify_password("wrong-password-1", h) is False


def test_verify_password_with_garbage_hash_is_false():
    assert verify_password("anything-at-all", "not-a-bcrypt-hash") is False


def test_verify_password_rejects_over_72_bytes():
    pw72 = "a" * 72
    h = hash_password(pw72)
    assert verify_password(pw72, h) is True
    # bcrypt alone would truncate and accept this; we must not.
    assert verify_password(pw72 + "extra", h) is False


@pytest.mark.parametrize("pw", ["short", "123456789", ""])
def test_password_too_short(pw):
    with pytest.raises(ValueError):
        validate_password_strength(pw)


def test_password_boundaries():
    assert validate_password_strength("a" * 10)
    assert validate_password_strength("a" * 72)
    with pytest.raises(ValueError):
        validate_password_strength("a" * 73)


def test_token_roundtrip():
    uid = uuid.uuid4()
    token, expires_in = create_access_token(uid)
    assert decode_access_token(token) == uid
    assert expires_in == get_settings().ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_token_contains_no_role_or_email():
    token, _ = create_access_token(uuid.uuid4())
    payload = jwt.decode(token, options={"verify_signature": False})
    assert set(payload) == {"sub", "iat", "exp", "jti"}


def test_tokens_are_unique():
    uid = uuid.uuid4()
    assert create_access_token(uid)[0] != create_access_token(uid)[0]


def test_expired_token_rejected():
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)},
        get_settings().JWT_SECRET, algorithm="HS256",
    )
    with pytest.raises(AuthenticationError):
        decode_access_token(token)


def test_tampered_token_rejected():
    token, _ = create_access_token(uuid.uuid4())
    head, payload, sig = token.split(".")
    tampered = ".".join([head, payload, sig[:-2] + ("AA" if not sig.endswith("AA") else "BB")])
    with pytest.raises(AuthenticationError):
        decode_access_token(tampered)


@pytest.mark.parametrize("alg", ["none", "HS1", "RS256", "", "hs256 "])
def test_insecure_jwt_algorithms_rejected_by_settings(alg):
    with pytest.raises(ValidationError):
        Settings(JWT_ALGORITHM=alg)


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_algorithms_allowed(alg):
    assert Settings(JWT_ALGORITHM=alg).JWT_ALGORITHM == alg
