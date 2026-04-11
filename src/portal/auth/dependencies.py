"""FastAPI dependencies for session-backed authentication."""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth.sessions import lookup_session
from portal.config import settings
from portal.db.models import User
from portal.db.session import get_db


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the current user from the session cookie, or raise 401."""
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="not_authenticated"
        )
    session = await lookup_session(db, cookie)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_session"
        )
    # Load the user. expire_on_commit=False means the relationship is lazy —
    # fetch explicitly via the primary key.
    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive_user"
        )
    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Only allow admin users. Non-admins get 403."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="admin_required"
        )
    return user
