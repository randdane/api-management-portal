"""Login rate limiting middleware.

Limits login attempts to 5 per minute per IP address using a Redis counter.
Only the POST /api/auth/login path is rate-limited; all other routes pass
through unconditionally.
"""

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from portal.cache.redis import get_client

logger = structlog.get_logger(__name__)

_LOGIN_PATH = "/api/auth/login"
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 60


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "POST" and request.url.path == _LOGIN_PATH:
            ip = request.client.host if request.client else "unknown"
            key = f"login_rate:{ip}"
            client = get_client()
            try:
                count = await client.incr(key)
                if count == 1:
                    await client.expire(key, _WINDOW_SECONDS)
                if count > _MAX_ATTEMPTS:
                    logger.warning(
                        "login.rate_limit_exceeded", ip=ip, count=count
                    )
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "too_many_login_attempts"},
                        headers={"Retry-After": str(_WINDOW_SECONDS)},
                    )
            except Exception as exc:
                # Fail open: if Redis is unavailable, don't block login
                logger.warning("login.rate_limit.redis_error", error=str(exc))
            finally:
                await client.aclose()

        return await call_next(request)
