"""Admin API and page routes — user management and audit logs.

All routes require admin role. Page routes serve full HTML on initial load
and SSE fragments on Datastar requests.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from portal.auth.dependencies import get_current_user, require_admin
from portal.auth.passwords import hash_password
from portal.db.models import ApiToken, AuditLog, Session, User
from portal.db.session import get_db
from portal.services.audit import log_action
from portal.sse import is_datastar_request, merge_fragments

router = APIRouter(tags=["admin"])
templates = Jinja2Templates(directory="src/portal/templates")


# ── Pages ──────────────────────────────────────────────────────────────────


@router.get("/admin/users")
async def users_page(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    users = await _list_users(db)
    ctx = {"request": request, "user": admin, "users": users}
    if is_datastar_request(request):
        html = templates.get_template("fragments/user_list.html").render(ctx)
        return merge_fragments(f'<div id="user-list">{html}</div>')
    return templates.TemplateResponse(request=request, name="admin_users.html", context=ctx)


@router.get("/admin/audit-logs")
async def audit_logs_page(
    request: Request,
    action: str = "",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    logs = await _query_audit_logs(db, action_filter=action or None)
    ctx = {"request": request, "user": admin, "logs": logs, "action_filter": action}
    if is_datastar_request(request):
        html = templates.get_template("fragments/audit_list.html").render(ctx)
        return merge_fragments(html)
    return templates.TemplateResponse(request=request, name="admin_audit.html", context=ctx)


# ── User management API ────────────────────────────────────────────────────


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"


class UserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


def _user_out(u: User) -> UserOut:
    return UserOut(
        id=str(u.id),
        username=u.username,
        email=u.email,
        role=u.role,
        is_active=u.is_active,
        created_at=u.created_at,
    )


@router.get("/api/admin/users", response_model=list[UserOut])
async def list_users_api(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[UserOut]:
    users = await _list_users(db)
    return [_user_out(u) for u in users]


@router.post("/api/admin/users", response_model=UserOut, status_code=201)
async def create_user_api(
    payload: UserCreateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    existing = await db.execute(
        select(User).where(User.username == payload.username)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username_taken"
        )
    existing_email = await db.execute(
        select(User).where(User.email == payload.email)
    )
    if existing_email.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="email_taken"
        )
    if payload.role not in ("admin", "user"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid_role"
        )

    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()

    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="user.created",
        resource_type="user",
        resource_id=str(new_user.id),
        details={"username": payload.username, "role": payload.role},
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(new_user)

    if is_datastar_request(request):
        users = await _list_users(db)
        ctx = {"request": request, "user": admin, "users": users}
        html = templates.get_template("fragments/user_list.html").render(ctx)
        return merge_fragments(f'<div id="user-list">{html}</div>')

    return _user_out(new_user)


@router.put("/api/admin/users/{user_id}", response_model=UserOut)
async def update_user_api(
    user_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    data = await request.json()
    payload = UserUpdateRequest(
        role=data.get("role"),
        is_active=data.get("is_active", data.get("isActive")),
    )

    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    if payload.role is not None and payload.role not in ("admin", "user"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid_role"
        )

    changes: dict = {}
    if payload.role is not None:
        target.role = payload.role
        changes["role"] = payload.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
        changes["is_active"] = payload.is_active
        if payload.is_active is False:
            # Immediate revocation of all access.
            await db.execute(delete(Session).where(Session.user_id == target.id))
            await db.execute(
                update(ApiToken)
                .where(ApiToken.user_id == target.id)
                .values(is_revoked=True)
            )

    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="user.updated",
        resource_type="user",
        resource_id=str(target.id),
        details=changes,
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(target)

    if is_datastar_request(request):
        users = await _list_users(db)
        ctx = {"request": request, "user": admin, "users": users}
        html = templates.get_template("fragments/user_list.html").render(ctx)
        return merge_fragments(f'<div id="user-list">{html}</div>')

    return _user_out(target)


@router.delete("/api/admin/users/{user_id}")
async def deactivate_user_api(
    user_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user_not_found")
    if str(target.id) == str(admin.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cannot_deactivate_self",
        )

    target.is_active = False
    # Immediate revocation of all access.
    await db.execute(delete(Session).where(Session.user_id == target.id))
    await db.execute(
        update(ApiToken).where(ApiToken.user_id == target.id).values(is_revoked=True)
    )

    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="user.deactivated",
        resource_type="user",
        resource_id=str(target.id),
        details={"username": target.username},
        ip_address=ip,
    )
    await db.commit()

    if is_datastar_request(request):
        users = await _list_users(db)
        ctx = {"request": request, "user": admin, "users": users}
        html = templates.get_template("fragments/user_list.html").render(ctx)
        return merge_fragments(f'<div id="user-list">{html}</div>')

    return {"status": "ok"}


# ── Admin UI user action endpoints (URL-encoded actions, return SSE fragments) ──


@router.put("/api/admin/users/{user_id}/role/{new_role}")
async def set_user_role_ui(
    user_id: uuid.UUID,
    new_role: str,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Set a user's role from the admin table; returns updated user-list fragment."""
    if new_role not in ("admin", "user"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid_role"
        )
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    target.role = new_role
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="user.updated",
        resource_type="user",
        resource_id=str(target.id),
        details={"role": new_role},
        ip_address=ip,
    )
    await db.commit()

    users = await _list_users(db)
    ctx = {"request": request, "user": admin, "users": users}
    html = templates.get_template("fragments/user_list.html").render(ctx)
    return merge_fragments(f'<div id="user-list">{html}</div>')


@router.put("/api/admin/users/{user_id}/activate")
async def activate_user_ui(
    user_id: uuid.UUID,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Reactivate a user from the admin table; returns updated user-list fragment."""
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    target.is_active = True
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="user.reactivated",
        resource_type="user",
        resource_id=str(target.id),
        details={"username": target.username},
        ip_address=ip,
    )
    await db.commit()

    users = await _list_users(db)
    ctx = {"request": request, "user": admin, "users": users}
    html = templates.get_template("fragments/user_list.html").render(ctx)
    return merge_fragments(f'<div id="user-list">{html}</div>')


# ── Audit log API ──────────────────────────────────────────────────────────


class AuditLogOut(BaseModel):
    id: str
    user_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    details: dict
    ip_address: str | None
    created_at: datetime


@router.get("/api/admin/audit-logs", response_model=list[AuditLogOut])
async def list_audit_logs_api(
    action: str = "",
    limit: int = 100,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLogOut]:
    logs = await _query_audit_logs(db, action_filter=action or None, limit=limit)
    return [
        AuditLogOut(
            id=str(log.id),
            user_id=str(log.user_id) if log.user_id else None,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            details=log.details,
            ip_address=log.ip_address,
            created_at=log.created_at,
        )
        for log in logs
    ]


# ── Helpers ────────────────────────────────────────────────────────────────


async def _list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


async def _query_audit_logs(
    db: AsyncSession,
    action_filter: str | None = None,
    limit: int = 100,
) -> list[AuditLog]:
    stmt = (
        select(AuditLog)
        .options(joinedload(AuditLog.user))
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    if action_filter:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action_filter}%"))
    result = await db.execute(stmt)
    return list(result.scalars().all())
