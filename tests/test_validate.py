"""Tests for the token validation endpoint business logic.

Covers: valid token, revoked token, expired token, inactive user, nonexistent token.
All DB interactions are mocked; HMAC signing uses the real signing helper.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from portal.auth.hmac_auth import sign_request
from portal.auth.tokens import generate_token, hash_token
from portal.config import settings
from portal.db.session import get_db
from portal.main import app

SECRET = settings.gateway_portal_shared_secret
VALIDATE_PATH = "/api/tokens/validate"


def _signed_request(token: str) -> tuple[bytes, dict[str, str]]:
    body = json.dumps({"token": token}).encode()
    ts, sig = sign_request(SECRET, "POST", VALIDATE_PATH, body)
    headers = {
        "X-Portal-Timestamp": ts,
        "X-Portal-Signature": sig,
        "content-type": "application/json",
    }
    return body, headers


def _make_token_user_row(
    *,
    is_revoked: bool = False,
    expires_at: datetime | None = None,
    is_active: bool = True,
) -> tuple[MagicMock, MagicMock]:
    """Build fake (ApiToken, User) row mocks."""
    token = MagicMock()
    token.is_revoked = is_revoked
    token.expires_at = expires_at
    token.last_used_at = None

    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "alice@example.com"
    user.role = "user"
    user.is_active = is_active

    return token, user


def _db_with_row(row) -> callable:
    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.first.return_value = row
    fake_session.execute = AsyncMock(return_value=fake_result)
    fake_session.commit = AsyncMock()

    async def _fake_db():
        yield fake_session

    return _fake_db


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.pop(get_db, None)


def test_valid_token_returns_user_identity():
    plain, token_hash, _ = generate_token()
    token, user = _make_token_user_row()
    app.dependency_overrides[get_db] = _db_with_row((token, user))

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["user_id"] == str(user.id)
    assert data["email"] == "alice@example.com"
    assert data["role"] == "user"


def test_revoked_token_returns_invalid():
    plain, _, _ = generate_token()
    token, user = _make_token_user_row(is_revoked=True)
    app.dependency_overrides[get_db] = _db_with_row((token, user))

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"valid": False, "user_id": None, "email": None, "role": None}


def test_expired_token_returns_invalid():
    plain, _, _ = generate_token()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token, user = _make_token_user_row(expires_at=past)
    app.dependency_overrides[get_db] = _db_with_row((token, user))

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"valid": False, "user_id": None, "email": None, "role": None}


def test_inactive_user_returns_invalid():
    plain, _, _ = generate_token()
    token, user = _make_token_user_row(is_active=False)
    app.dependency_overrides[get_db] = _db_with_row((token, user))

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"valid": False, "user_id": None, "email": None, "role": None}


def test_nonexistent_token_returns_invalid():
    plain, _, _ = generate_token()
    app.dependency_overrides[get_db] = _db_with_row(None)

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    assert resp.json() == {"valid": False, "user_id": None, "email": None, "role": None}


def test_non_expired_token_is_valid():
    plain, _, _ = generate_token()
    future = datetime.now(timezone.utc) + timedelta(days=30)
    token, user = _make_token_user_row(expires_at=future)
    app.dependency_overrides[get_db] = _db_with_row((token, user))

    body, headers = _signed_request(plain)
    resp = TestClient(app).post(VALIDATE_PATH, content=body, headers=headers)

    assert resp.status_code == 200
    assert resp.json()["valid"] is True
