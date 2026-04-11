"""DB-backed session management.

A session is a random 32-byte token stored in the client's cookie. The
database stores only the SHA-256 hash of the token, so a DB dump cannot be
used to impersonate active sessions. Expiry is enforced server-side on
every lookup.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.config import settings
from portal.db.models import Session


def _hash_token(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    """Return a cryptographically strong random session token."""
    return secrets.token_urlsafe(32)


async def create_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> str:
    """Create a new session row and return the plaintext token to set in a cookie."""
    plain = generate_session_token()
    token_hash = _hash_token(plain)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.session_ttl_seconds
    )
    row = Session(
        user_id=user_id,
        session_token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )
    db.add(row)
    await db.flush()
    return plain


async def lookup_session(db: AsyncSession, plain: str) -> Session | None:
    """Return the matching Session row if valid and unexpired, else None."""
    token_hash = _hash_token(plain)
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        return None
    return row


async def invalidate_session(db: AsyncSession, plain: str) -> Session | None:
    """Delete the session row matching the given plaintext token. Returns the deleted row, or None."""
    token_hash = _hash_token(plain)
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None:
        await db.delete(row)
        return row
    return None
