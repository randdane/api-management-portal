"""HMAC request signing for the gateway → portal validate endpoint.

The caller (gateway) signs a canonical string over a few request components
so that:
  - the timestamp gives freshness (short acceptance window)
  - method + path prevent cross-endpoint replay
  - a hash of the body prevents tampering

Canonical string:
    "{timestamp}\n{METHOD}\n{path}\n{sha256_hex(body)}"

Headers:
    X-Portal-Timestamp: <unix epoch seconds>
    X-Portal-Signature: <hex HMAC-SHA256 of canonical string>

The portal rejects any request that is missing headers, has an out-of-window
timestamp, or whose recomputed signature does not match.
"""

import hashlib
import hmac
import time

from fastapi import HTTPException, Request, status

from portal.config import settings

TIMESTAMP_HEADER = "x-portal-timestamp"
SIGNATURE_HEADER = "x-portal-signature"


def canonical_string(timestamp: str, method: str, path: str, body: bytes) -> str:
    """Build the canonical string that gets HMAC'd.

    Path should be the request path only (no query string) -- matches what
    the portal sees in request.url.path. Method should be uppercase.
    """
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{method.upper()}\n{path}\n{body_hash}"


def compute_signature(secret: str, canonical: str) -> str:
    """Return hex HMAC-SHA256 of canonical using the given secret."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int | None = None,
) -> tuple[str, str]:
    """Produce (timestamp_str, signature_hex) for a request.

    Callers pass the returned values in the X-Portal-Timestamp and
    X-Portal-Signature headers. This helper exists so the gateway (or tests)
    can sign requests symmetrically with how the portal verifies them.
    """
    ts = str(timestamp if timestamp is not None else int(time.time()))
    canonical = canonical_string(ts, method, path, body)
    signature = compute_signature(secret, canonical)
    return ts, signature


async def require_valid_hmac(request: Request) -> None:
    """FastAPI dependency that rejects requests without a valid HMAC signature.

    Raises 401 for:
      - missing X-Portal-Timestamp or X-Portal-Signature
      - malformed timestamp
      - timestamp outside the acceptance window
      - signature mismatch (constant-time compare)

    Reads and caches the raw request body so downstream handlers can still
    access it via request.json() or request.body().
    """
    timestamp = request.headers.get(TIMESTAMP_HEADER)
    signature = request.headers.get(SIGNATURE_HEADER)
    if not timestamp or not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing_hmac_headers",
        )

    try:
        ts_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="malformed_timestamp",
        ) from exc

    now = int(time.time())
    window = settings.hmac_timestamp_window_seconds
    if abs(now - ts_int) > window:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="timestamp_out_of_window",
        )

    # Read and cache the raw body. Starlette caches this on the Request
    # object so request.json() later returns the same bytes.
    body = await request.body()

    canonical = canonical_string(
        timestamp, request.method, request.url.path, body
    )
    expected = compute_signature(settings.gateway_portal_shared_secret, canonical)
    if not hmac.compare_digest(expected.encode(), signature.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_signature",
        )
