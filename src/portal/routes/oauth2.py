"""OAuth2 authorization code flow routes.

GET  /api/auth/oauth2/authorize  — redirect to IdP
GET  /api/auth/oauth2/callback   — handle IdP callback, create session

Disabled (returns 404) when OAUTH2_CLIENT_ID is not configured.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth import oauth2 as oauth2_lib
from portal.auth.sessions import create_session
from portal.config import settings
from portal.db.session import get_db
from portal.services.audit import log_action

router = APIRouter(prefix="/api/auth/oauth2", tags=["oauth2"])

_STATE_COOKIE = "oauth2_state"


def _require_configured():
    if not oauth2_lib.is_configured():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="oauth2_not_configured",
        )


@router.get("/authorize")
async def authorize(request: Request):
    _require_configured()
    state = oauth2_lib.generate_state()
    url = oauth2_lib.build_authorize_url(state)
    response = RedirectResponse(url, status_code=302)
    # Store state in a short-lived cookie to verify on callback
    response.set_cookie(
        key=_STATE_COOKIE,
        value=state,
        max_age=600,
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/callback")
async def callback(
    request: Request,
    response: Response,
    code: str = "",
    state: str = "",
    error: str = "",
    db: AsyncSession = Depends(get_db),
):
    _require_configured()

    def _clear_state(resp: RedirectResponse) -> RedirectResponse:
        """Remove the state cookie from any response (error or success)."""
        resp.delete_cookie(
            _STATE_COOKIE,
            path="/",
            httponly=True,
            secure=settings.require_https,
            samesite="lax",
        )
        return resp

    if error:
        return _clear_state(RedirectResponse(f"/login?error={error}", status_code=302))

    # Verify state to prevent CSRF on the callback
    cookie_state = request.cookies.get(_STATE_COOKIE)
    if not cookie_state or not state or cookie_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_state",
        )

    http_client = request.app.state.http_client

    try:
        tokens = await oauth2_lib.exchange_code(code, http_client)
        userinfo = await oauth2_lib.fetch_userinfo(
            tokens["access_token"], http_client
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="oauth2_exchange_failed",
        ) from exc

    provider = settings.oauth2_provider_name or "oauth2"
    subject = userinfo.get("sub", "")
    email = userinfo.get("email", "")
    username = userinfo.get("preferred_username", "") or userinfo.get("name", "")

    # Validate that the IdP returned the minimum required claims.
    if not subject or not email:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="oauth2_missing_claims",
        )

    user = await oauth2_lib.find_or_create_oauth_user(
        db, provider=provider, subject=subject, email=email, username=username
    )

    ip = request.client.host if request.client else None
    session_token = await create_session(db, user.id, ip_address=ip)
    await log_action(
        db,
        user_id=user.id,
        action="user.login_oauth2",
        resource_type="user",
        resource_id=str(user.id),
        details={"provider": provider},
        ip_address=ip,
    )
    await db.commit()

    redirect = RedirectResponse("/", status_code=302)
    redirect.delete_cookie(
        _STATE_COOKIE,
        path="/",
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
    )
    redirect.set_cookie(
        key=settings.session_cookie_name,
        value=session_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
        path="/",
    )
    return redirect
