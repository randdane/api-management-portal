"""Tests for HMAC request signing on the validate endpoint.

Covers the four cases explicitly called out in the plan:
  1. Correct canonicalization — valid HMAC over the canonical string is accepted
  2. Out-of-window timestamp — old or future timestamps are rejected
  3. Wrong method or path — signature computed against a different method/path is rejected
  4. Bad signature — any tampering with the signature hex is rejected

Tests bypass the database by overriding get_db with a fake session that
raises if called on HMAC-failure paths (ensuring HMAC check runs first)
and returns a fake valid-token row on the happy path.
"""

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from portal.auth.hmac_auth import (
    canonical_string,
    compute_signature,
    sign_request,
)
from portal.config import settings
from portal.db.session import get_db
from portal.main import app

SECRET = settings.gateway_portal_shared_secret
VALIDATE_PATH = "/api/tokens/validate"


def _signed_headers(
    body: bytes,
    *,
    method: str = "POST",
    path: str = VALIDATE_PATH,
    timestamp: int | None = None,
) -> dict[str, str]:
    ts, sig = sign_request(SECRET, method, path, body, timestamp=timestamp)
    return {
        "X-Portal-Timestamp": ts,
        "X-Portal-Signature": sig,
        "content-type": "application/json",
    }


@pytest.fixture
def client_no_db():
    """TestClient whose DB dependency raises if touched.

    Use for tests that expect HMAC rejection BEFORE any DB work happens.
    """

    async def _raise_if_called():
        raise AssertionError(
            "get_db should not be called on HMAC-failure paths"
        )
        yield  # pragma: no cover

    app.dependency_overrides[get_db] = _raise_if_called
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client_with_invalid_token_db():
    """TestClient whose DB returns no matching token (so response = valid:false).

    Use for happy-path HMAC tests where we just want the request to reach
    the handler without actually needing a real token in the DB.
    """
    fake_session = MagicMock()
    fake_result = MagicMock()
    fake_result.first.return_value = None
    fake_session.execute = AsyncMock(return_value=fake_result)
    fake_session.commit = AsyncMock()

    async def _fake_db():
        yield fake_session

    app.dependency_overrides[get_db] = _fake_db
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)


# ----- canonicalization (unit-level) ----------------------------------


def test_canonical_string_format():
    body = b'{"token": "tok_abc"}'
    canonical = canonical_string("1700000000", "POST", "/api/tokens/validate", body)
    # Must have exactly 4 lines separated by \n.
    parts = canonical.split("\n")
    assert len(parts) == 4
    assert parts[0] == "1700000000"
    assert parts[1] == "POST"
    assert parts[2] == "/api/tokens/validate"
    # Body hash is sha256 hex of the body bytes.
    import hashlib
    assert parts[3] == hashlib.sha256(body).hexdigest()


def test_canonical_string_method_is_uppercased():
    body = b""
    upper = canonical_string("1700000000", "POST", "/x", body)
    lower = canonical_string("1700000000", "post", "/x", body)
    assert upper == lower


def test_compute_signature_is_deterministic():
    canonical = "1700000000\nPOST\n/api/tokens/validate\nabc"
    sig1 = compute_signature(SECRET, canonical)
    sig2 = compute_signature(SECRET, canonical)
    assert sig1 == sig2
    # Different secret -> different signature
    assert compute_signature("other", canonical) != sig1


def test_compute_signature_changes_with_any_input():
    base = canonical_string("1700000000", "POST", "/a", b"")
    sig = compute_signature(SECRET, base)
    # Timestamp change
    assert compute_signature(
        SECRET, canonical_string("1700000001", "POST", "/a", b"")
    ) != sig
    # Method change
    assert compute_signature(
        SECRET, canonical_string("1700000000", "GET", "/a", b"")
    ) != sig
    # Path change
    assert compute_signature(
        SECRET, canonical_string("1700000000", "POST", "/b", b"")
    ) != sig
    # Body change
    assert compute_signature(
        SECRET, canonical_string("1700000000", "POST", "/a", b"x")
    ) != sig


# ----- endpoint-level HMAC tests --------------------------------------


def test_valid_hmac_reaches_handler(client_with_invalid_token_db):
    body = json.dumps({"token": "tok_doesnotexist"}).encode()
    headers = _signed_headers(body)
    resp = client_with_invalid_token_db.post(
        VALIDATE_PATH, content=body, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json() == {"valid": False, "user_id": None, "email": None, "role": None}


def test_missing_signature_header_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    resp = client_no_db.post(
        VALIDATE_PATH,
        content=body,
        headers={
            "X-Portal-Timestamp": str(int(time.time())),
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_hmac_headers"


def test_missing_timestamp_header_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    canonical = canonical_string(
        str(int(time.time())), "POST", VALIDATE_PATH, body
    )
    sig = compute_signature(SECRET, canonical)
    resp = client_no_db.post(
        VALIDATE_PATH,
        content=body,
        headers={
            "X-Portal-Signature": sig,
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_hmac_headers"


def test_malformed_timestamp_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    resp = client_no_db.post(
        VALIDATE_PATH,
        content=body,
        headers={
            "X-Portal-Timestamp": "not-a-number",
            "X-Portal-Signature": "deadbeef",
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "malformed_timestamp"


def test_out_of_window_old_timestamp_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    old_ts = int(time.time()) - (settings.hmac_timestamp_window_seconds + 5)
    headers = _signed_headers(body, timestamp=old_ts)
    resp = client_no_db.post(VALIDATE_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "timestamp_out_of_window"


def test_out_of_window_future_timestamp_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    future_ts = int(time.time()) + (settings.hmac_timestamp_window_seconds + 5)
    headers = _signed_headers(body, timestamp=future_ts)
    resp = client_no_db.post(VALIDATE_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "timestamp_out_of_window"


def test_wrong_path_in_signature_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    # Sign for a different path, but send to the real one.
    headers = _signed_headers(body, path="/api/some-other-endpoint")
    resp = client_no_db.post(VALIDATE_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_signature"


def test_wrong_method_in_signature_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    # Sign as GET but send via POST.
    headers = _signed_headers(body, method="GET")
    resp = client_no_db.post(VALIDATE_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_signature"


def test_tampered_body_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    headers = _signed_headers(body)
    # Send a different body than the one that was signed.
    tampered = json.dumps({"token": "tok_y"}).encode()
    resp = client_no_db.post(VALIDATE_PATH, content=tampered, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_signature"


def test_bad_signature_hex_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    ts, _sig = sign_request(SECRET, "POST", VALIDATE_PATH, body)
    resp = client_no_db.post(
        VALIDATE_PATH,
        content=body,
        headers={
            "X-Portal-Timestamp": ts,
            "X-Portal-Signature": "00" * 32,
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_signature"


def test_wrong_secret_rejected(client_no_db):
    body = json.dumps({"token": "tok_x"}).encode()
    ts, sig = sign_request("some-other-secret", "POST", VALIDATE_PATH, body)
    resp = client_no_db.post(
        VALIDATE_PATH,
        content=body,
        headers={
            "X-Portal-Timestamp": ts,
            "X-Portal-Signature": sig,
            "content-type": "application/json",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_signature"
