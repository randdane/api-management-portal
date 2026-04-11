"""OAuth2 authorization code flow.

This module implements the standard OAuth2 authorization code flow for
browser-based login via an external identity provider (e.g., Google, Auth0,
Keycloak).

Configuration (all optional — OAuth2 is disabled if OAUTH2_CLIENT_ID is empty):
    OAUTH2_CLIENT_ID         Client ID from the IdP
    OAUTH2_CLIENT_SECRET     Client secret from the IdP
    OAUTH2_PROVIDER_NAME     Stable provider key (e.g. "google", "auth0")
    OAUTH2_AUTHORIZE_URL     Authorization endpoint URL
    OAUTH2_TOKEN_URL         Token endpoint URL
    OAUTH2_USERINFO_URL      Userinfo endpoint URL
    OAUTH2_SCOPES            Space-separated scopes (default: "openid email profile")
    OAUTH2_REDIRECT_URI      Callback URL (default: {portal_base_url}/api/auth/oauth2/callback)

Flow:
    1. User visits GET /api/auth/oauth2/authorize
    2. Portal redirects to IdP with state param (anti-CSRF nonce in session)
    3. IdP redirects back to GET /api/auth/oauth2/callback?code=...&state=...
    4. Portal exchanges code for tokens, fetches userinfo
    5. Portal finds or creates local User (matched on oauth_provider + oauth_subject)
    6. Portal creates session, sets cookie, redirects to /
"""

import hashlib
import secrets
from urllib.parse import urlencode

import httpx
import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.config import settings
from portal.db.models import User

logger = structlog.get_logger(__name__)


def is_configured() -> bool:
    """Return True if OAuth2 credentials are present in settings."""
    return bool(
        getattr(settings, "oauth2_client_id", None)
        and getattr(settings, "oauth2_authorize_url", None)
    )


def build_authorize_url(state: str) -> str:
    """Build the IdP authorization URL with the given state nonce."""
    params = {
        "client_id": settings.oauth2_client_id,
        "response_type": "code",
        "redirect_uri": settings.oauth2_redirect_uri,
        "scope": getattr(settings, "oauth2_scopes", "openid email profile"),
        "state": state,
    }
    return f"{settings.oauth2_authorize_url}?{urlencode(params)}"


async def exchange_code(
    code: str,
    http_client: httpx.AsyncClient,
) -> dict:
    """Exchange authorization code for tokens. Returns the token response dict."""
    resp = await http_client.post(
        settings.oauth2_token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oauth2_redirect_uri,
            "client_id": settings.oauth2_client_id,
            "client_secret": settings.oauth2_client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    return resp.json()


async def fetch_userinfo(
    access_token: str,
    http_client: httpx.AsyncClient,
) -> dict:
    """Fetch user profile from the IdP userinfo endpoint."""
    resp = await http_client.get(
        settings.oauth2_userinfo_url,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp.raise_for_status()
    return resp.json()


async def find_or_create_oauth_user(
    db: AsyncSession,
    provider: str,
    subject: str,
    email: str,
    username: str,
) -> User:
    """Return the existing user for this OAuth identity, or create one.

    The partial unique index on (oauth_provider, oauth_subject) ensures
    a given external identity maps to exactly one local user.
    """
    stmt = select(User).where(
        User.oauth_provider == provider,
        User.oauth_subject == subject,
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is not None:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="inactive_user",
            )
        return user

    # Create new user — derive a unique username if taken
    base_username = username or email.split("@")[0]
    candidate = base_username
    for suffix in range(1, 100):
        existing = await db.execute(select(User).where(User.username == candidate))
        if existing.scalar_one_or_none() is None:
            break
        candidate = f"{base_username}{suffix}"

    new_user = User(
        username=candidate,
        email=email,
        oauth_provider=provider,
        oauth_subject=subject,
        role="user",
        is_active=True,
    )
    db.add(new_user)
    await db.flush()
    logger.info(
        "oauth2.user_created",
        provider=provider,
        subject_hash=hashlib.sha256(subject.encode()).hexdigest()[:8],
        username=candidate,
    )
    return new_user


def generate_state() -> str:
    """Generate a cryptographically strong state nonce for CSRF protection."""
    return secrets.token_urlsafe(32)
