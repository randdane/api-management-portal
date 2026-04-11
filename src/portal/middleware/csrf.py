"""CSRF protection middleware.

Strategy: Double-submit cookie pattern.
- On every response, set a `csrf_token` cookie (non-HttpOnly so JS/Datastar
  can read it).
- On state-changing requests (POST, PUT, PATCH, DELETE) to /api/* paths,
  verify that the X-CSRF-Token header matches the cookie value.
- Exempt: /api/auth/login (pre-auth), /api/tokens/validate (gateway-facing,
  HMAC-protected instead), and any non-/api/* path (page renders).

The token is a random 32-byte urlsafe value stored directly in the cookie.
JS reads the cookie and sends the same value in the X-CSRF-Token header.
"""

import secrets

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from portal.config import settings

logger = structlog.get_logger(__name__)

_CSRF_COOKIE = "csrf_token"
_CSRF_HEADER = "x-csrf-token"

# Paths exempt from CSRF verification (pre-auth or non-browser callers)
_EXEMPT_PATHS = {
    "/api/auth/login",
    "/api/tokens/validate",
}

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _make_token() -> str:
    return secrets.token_urlsafe(32)


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Only enforce on /api/* mutating requests not in the exempt list
        if (
            request.method in _MUTATING_METHODS
            and path.startswith("/api/")
            and path not in _EXEMPT_PATHS
        ):
            cookie_token = request.cookies.get(_CSRF_COOKIE)
            header_token = request.headers.get(_CSRF_HEADER)

            if not cookie_token or not header_token:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "csrf_token_missing"},
                )

            if not secrets.compare_digest(cookie_token, header_token):
                logger.warning("csrf.rejected", path=path, method=request.method)
                return JSONResponse(
                    status_code=403,
                    content={"detail": "csrf_token_invalid"},
                )

        response = await call_next(request)

        # Ensure a CSRF cookie is always present on HTML responses
        if _CSRF_COOKIE not in request.cookies:
            token = _make_token()
            response.set_cookie(
                key=_CSRF_COOKIE,
                value=token,
                # NOT HttpOnly — Datastar/JS must be able to read it
                httponly=False,
                secure=settings.require_https,
                samesite="lax",
                path="/",
            )

        return response
