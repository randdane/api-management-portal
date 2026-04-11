"""Tests for Datastar-driven UI flows on shared endpoints."""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from portal.auth.dependencies import get_current_user, require_admin
from portal.config import settings
from portal.db.models import ApiToken
from portal.db.session import get_db
from portal.main import app
from portal.middleware.csrf import _CSRF_COOKIE, _CSRF_HEADER, _make_token


def _client_with_csrf() -> TestClient:
    token = _make_token()
    client = TestClient(app)
    client.cookies.set(_CSRF_COOKIE, token)
    client.headers.update({_CSRF_HEADER: token})
    return client


def _make_user(*, role: str = "user", active: bool = True) -> MagicMock:
    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "alice@example.com"
    user.username = "alice"
    user.role = role
    user.is_active = active
    user.password_hash = "hashed-password"
    user.created_at = datetime.now(timezone.utc)
    return user


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(require_admin, None)


@pytest.fixture(autouse=True)
def _mock_rate_limit_redis():
    client = SimpleNamespace(
        incr=AsyncMock(return_value=1),
        expire=AsyncMock(),
        aclose=AsyncMock(),
    )
    with patch("portal.middleware.rate_limit.get_client", return_value=client):
        yield


def test_login_datastar_sets_session_cookie_and_redirect_signal():
    user = _make_user()
    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.scalar_one_or_none.return_value = user
    fake_session.execute = AsyncMock(return_value=fake_result)
    fake_session.commit = AsyncMock()
    fake_session.flush = AsyncMock()

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db

    with (
        patch("portal.routes.auth.verify_password", return_value=True),
        patch("portal.routes.auth.create_session", new=AsyncMock(return_value="session-token")),
    ):
        resp = TestClient(app).post(
            "/api/auth/login",
            json={"username": "alice", "password": "secret"},
            headers={"datastar-request": "true"},
        )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "datastar-merge-signals" in resp.text
    assert '"redirect": "/"' in resp.text
    assert settings.session_cookie_name in resp.headers["set-cookie"]


def test_logout_datastar_clears_cookie_and_redirect_signal():
    fake_session = MagicMock()
    fake_session.commit = AsyncMock()
    fake_session.flush = AsyncMock()

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()
    client.cookies.set(settings.session_cookie_name, "session-token")

    with patch(
        "portal.routes.auth.invalidate_session",
        new=AsyncMock(return_value=SimpleNamespace(user_id=str(uuid.uuid4()))),
    ):
        resp = client.post(
            "/api/auth/logout",
            headers={"datastar-request": "true", _CSRF_HEADER: client.headers[_CSRF_HEADER]},
        )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert '"redirect": "/login"' in resp.text
    assert settings.session_cookie_name in resp.headers["set-cookie"]
    assert "max-age=0" in resp.headers["set-cookie"].lower()


def test_create_token_datastar_uses_shared_api_endpoint():
    user = _make_user()
    token_row = ApiToken(
        user_id=user.id,
        name="my token",
        token_hash="hash",
        token_prefix="tok_test",
        expires_at=None,
        is_revoked=False,
    )
    token_row.id = uuid.uuid4()
    token_row.created_at = datetime.now(timezone.utc)

    async def _get_user():
        return user

    app.dependency_overrides[get_current_user] = _get_user

    fake_session = MagicMock()
    fake_session.add = MagicMock()
    fake_session.flush = AsyncMock()
    fake_session.commit = AsyncMock()
    fake_session.refresh = AsyncMock(side_effect=lambda row: None)
    fake_result = MagicMock()
    fake_result.scalars.return_value.all.return_value = [token_row]
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()

    with patch(
        "portal.routes.tokens.generate_token",
        return_value=("tok_plaintext", "hash", "tok_test"),
    ):
        resp = client.post(
            "/api/tokens",
            json={"name": "my token", "expiresAt": None},
            headers={"datastar-request": "true", _CSRF_HEADER: client.headers[_CSRF_HEADER]},
        )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert 'id="token-reveal-area"' in resp.text
    assert 'id="token-list"' in resp.text
    assert "tok_plaintext" in resp.text


def test_update_user_datastar_returns_updated_user_list_fragment():
    admin = _make_user(role="admin")
    target = _make_user(role="user")

    async def _require_admin():
        return admin

    app.dependency_overrides[require_admin] = _require_admin

    fake_session = MagicMock()
    fake_session.get = AsyncMock(return_value=target)
    fake_session.add = MagicMock()
    fake_session.commit = AsyncMock()
    fake_session.flush = AsyncMock()
    fake_session.refresh = AsyncMock(side_effect=lambda row: None)
    fake_result = MagicMock()
    fake_result.scalars.return_value.all.return_value = [target]
    fake_session.execute = AsyncMock(return_value=fake_result)

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()

    resp = client.put(
        f"/api/admin/users/{target.id}",
        json={"role": "admin", "isActive": "false"},
        headers={"datastar-request": "true", _CSRF_HEADER: client.headers[_CSRF_HEADER]},
    )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert 'id="user-list"' in resp.text
    assert target.username in resp.text


def test_deactivate_vendor_admin_view_returns_admin_fragment():
    admin = _make_user(role="admin")

    async def _require_admin():
        return admin

    app.dependency_overrides[require_admin] = _require_admin

    fake_session = MagicMock()
    fake_session.add = MagicMock()
    fake_session.commit = AsyncMock()
    fake_session.flush = AsyncMock()

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    client = _client_with_csrf()

    gateway = SimpleNamespace(
        deactivate_vendor=AsyncMock(return_value=True),
        list_vendors=AsyncMock(
            return_value=[
                {
                    "id": "vendor-1",
                    "name": "Vendor One",
                    "slug": "vendor-one",
                    "auth_type": "key",
                    "is_active": False,
                }
            ]
        ),
    )

    with patch("portal.routes.vendors._get_gateway_client", return_value=gateway):
        resp = client.delete(
            "/api/vendors/vendor-1?view=admin",
            headers={"datastar-request": "true", _CSRF_HEADER: client.headers[_CSRF_HEADER]},
        )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert 'id="vendor-admin-list"' in resp.text
    assert "Vendor One" in resp.text
    assert "Inactive" in resp.text
