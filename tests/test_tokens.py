"""Tests for the token management API (list, create, revoke).

Uses FastAPI dependency overrides to bypass session auth and the database.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from portal.auth.dependencies import get_current_user
from portal.db.session import get_db
from portal.main import app
from portal.middleware.csrf import _make_token, _CSRF_COOKIE, _CSRF_HEADER


def _client_with_csrf() -> TestClient:
    """Return a TestClient with pre-set CSRF cookie + header for mutating requests."""
    token = _make_token()
    client = TestClient(app)
    client.cookies.set(_CSRF_COOKIE, token)
    client.headers.update({_CSRF_HEADER: token})
    return client


def _make_user(role: str = "user") -> MagicMock:
    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "alice@example.com"
    user.username = "alice"
    user.role = role
    user.is_active = True
    return user


def _make_token_row(user_id: uuid.UUID, name: str = "test", is_revoked: bool = False) -> MagicMock:
    row = MagicMock()
    row.id = uuid.uuid4()
    row.user_id = user_id
    row.name = name
    row.token_hash = "abc"
    row.token_prefix = "tok_abcd"
    row.expires_at = None
    row.last_used_at = None
    row.is_revoked = is_revoked
    row.created_at = datetime.now(timezone.utc)
    return row


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)


def _auth_as(user: MagicMock):
    async def _get_user():
        return user
    app.dependency_overrides[get_current_user] = _get_user


def test_list_tokens_returns_empty_list():
    user = _make_user()
    _auth_as(user)

    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalars.return_value.all.return_value = []
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    resp = TestClient(app).get("/api/tokens")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_tokens_returns_prefix_not_hash():
    user = _make_user()
    _auth_as(user)

    token_row = _make_token_row(user.id)
    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalars.return_value.all.return_value = [token_row]
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    resp = TestClient(app).get("/api/tokens")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["token_prefix"] == "tok_abcd"
    assert "token_hash" not in data[0]


def test_create_token_returns_plain_token_once():
    user = _make_user()
    _auth_as(user)

    token_row = _make_token_row(user.id, name="my token")
    token_row.token_prefix = "tok_plai"

    fake_session = MagicMock()
    fake_session.add = MagicMock()
    fake_session.flush = AsyncMock()
    fake_session.commit = AsyncMock()
    fake_session.refresh = AsyncMock(side_effect=lambda r: None)
    fake_session.execute = AsyncMock(return_value=MagicMock())

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db

    client = _client_with_csrf()
    with patch("portal.routes.tokens.ApiToken") as MockToken, \
         patch("portal.routes.tokens.generate_token", return_value=("tok_plaintext", "hash", "tok_plai")):
        MockToken.return_value = token_row
        resp = client.post(
            "/api/tokens",
            json={"name": "my token", "expires_at": None},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["token"].startswith("tok_")
    assert "token" in data  # plain token present in create response


def test_revoke_token_not_found_returns_404():
    user = _make_user()
    _auth_as(user)

    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalar_one_or_none.return_value = None
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()
    resp = client.delete(f"/api/tokens/{uuid.uuid4()}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "token_not_found"


def test_revoke_token_success():
    user = _make_user()
    _auth_as(user)

    token_row = _make_token_row(user.id)

    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalar_one_or_none.return_value = token_row
    fake_session.execute = AsyncMock(return_value=fake_result)
    fake_session.commit = AsyncMock()

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db

    client = _client_with_csrf()
    with patch("portal.routes.tokens.log_action", new_callable=AsyncMock):
        resp = client.delete(f"/api/tokens/{token_row.id}")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert token_row.is_revoked is True


def test_revoke_already_revoked_token_is_idempotent():
    user = _make_user()
    _auth_as(user)

    token_row = _make_token_row(user.id, is_revoked=True)

    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalar_one_or_none.return_value = token_row
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()
    resp = client.delete(f"/api/tokens/{token_row.id}")
    assert resp.status_code == 200
    assert resp.json().get("already_revoked") is True


def test_unauthenticated_list_returns_401():
    resp = TestClient(app).get("/api/tokens")
    assert resp.status_code == 401
