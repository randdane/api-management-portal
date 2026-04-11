"""Username/password login, logout, and /api/me."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth.dependencies import get_current_user
from portal.auth.passwords import verify_password
from portal.auth.sessions import create_session, invalidate_session
from portal.config import settings
from portal.db.models import User
from portal.db.session import get_db
from portal.services.audit import log_action

router = APIRouter(prefix="/api/auth", tags=["auth"])
me_router = APIRouter(prefix="/api", tags=["me"])


class LoginRequest(BaseModel):
    username: str
    password: str


class UserProfile(BaseModel):
    id: str
    email: str
    username: str
    role: str
    is_active: bool


@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(User.username == payload.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None or user.password_hash is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive_user"
        )
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials"
        )

    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    token = await create_session(db, user.id, ip_address=ip, user_agent=ua)
    await log_action(
        db,
        user_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=ip,
    )
    await db.commit()

    cookie_kwargs = dict(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.require_https,
        samesite="lax",
        path="/",
    )

    # If Datastar made the request, return a redirect signal.
    # Otherwise return JSON (for API / curl usage).
    from portal.sse import is_datastar_request, merge_signals
    if is_datastar_request(request):
        resp = merge_signals({"redirect": "/"})
        resp.set_cookie(**cookie_kwargs)
        return resp

    resp = JSONResponse(content={"status": "ok", "user": UserProfile(
        id=str(user.id),
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
    ).model_dump()})
    resp.set_cookie(**cookie_kwargs)
    return resp


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        user = await invalidate_session(db, cookie)
        if user is not None:
            ip = request.client.host if request.client else None
            await log_action(
                db,
                user_id=user.user_id,
                action="user.logout",
                resource_type="user",
                resource_id=str(user.user_id),
                ip_address=ip,
            )
        await db.commit()

    delete_cookie_kwargs = {
        "key": settings.session_cookie_name,
        "path": "/",
    }

    from portal.sse import is_datastar_request, merge_signals

    if is_datastar_request(request):
        resp = merge_signals({"redirect": "/login"})
        resp.delete_cookie(**delete_cookie_kwargs)
        return resp

    resp = JSONResponse(content={"status": "ok"})
    resp.delete_cookie(**delete_cookie_kwargs)
    return resp


@me_router.get("/me", response_model=UserProfile)
async def me(user: User = Depends(get_current_user)) -> UserProfile:
    return UserProfile(
        id=str(user.id),
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
    )


class MeUpdateRequest(BaseModel):
    email: str | None = None
    password: str | None = None


@me_router.put("/me", response_model=UserProfile)
async def update_me(
    payload: MeUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserProfile:
    from portal.auth.passwords import hash_password
    if payload.email is not None:
        user.email = payload.email
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    await log_action(
        db,
        user_id=user.id,
        action="user.profile_updated",
        resource_type="user",
        resource_id=str(user.id),
        details={k: ("***" if k == "password" else v) for k, v in payload.model_dump(exclude_none=True).items()},
    )
    await db.commit()
    await db.refresh(user)
    return UserProfile(
        id=str(user.id),
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
    )
