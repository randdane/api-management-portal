"""Server-rendered page routes.

Each route serves a full HTML document on initial load and an SSE fragment
on Datastar interactions (detected via the datastar-request header).

Design note — dual-route pattern:
Token and vendor mutations have two separate endpoint families by design:
  - /api/tokens    and /api/vendors    → pure JSON API (used by gateway / curl / tests)
  - /api/tokens-ui and /api/vendors-ui → SSE fragment endpoints for Datastar browser flows

This keeps the JSON API stable for machine callers while letting the browser UI
receive morphable HTML fragments. The trade-off is some logic duplication; the
UI routes delegate to the same DB/gateway helpers as the API routes.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth import oauth2 as oauth2_lib
from portal.auth.dependencies import get_current_user
from portal.db.models import ApiToken, AuditLog, User
from portal.db.session import get_db
from portal.sse import is_datastar_request

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory="src/portal/templates")


# ── Login ──────────────────────────────────────────────────────────────────


@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "oauth2_enabled": oauth2_lib.is_configured()},
    )


@router.get("/")
async def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Token stats
    active_count_result = await db.execute(
        select(func.count()).where(
            ApiToken.user_id == user.id, ApiToken.is_revoked.is_(False)
        )
    )
    active_token_count = active_count_result.scalar() or 0

    total_count_result = await db.execute(
        select(func.count()).where(ApiToken.user_id == user.id)
    )
    total_token_count = total_count_result.scalar() or 0

    user_count = 0
    if user.role == "admin":
        uc_result = await db.execute(select(func.count()).select_from(User))
        user_count = uc_result.scalar() or 0

    logs_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
    )
    recent_logs = logs_result.scalars().all()

    ctx = {
        "request": request,
        "user": user,
        "active_token_count": active_token_count,
        "total_token_count": total_token_count,
        "user_count": user_count,
        "recent_logs": recent_logs,
    }
    return templates.TemplateResponse("dashboard.html", ctx)


# ── Tokens page ────────────────────────────────────────────────────────────


@router.get("/tokens")
async def tokens_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    tokens = await _get_user_tokens(user, db)
    ctx = {"request": request, "user": user, "tokens": tokens}

    if is_datastar_request(request):
        html = templates.get_template("fragments/token_list.html").render(ctx)
        from portal.sse import merge_fragments

        return merge_fragments(f'<div id="token-list">{html}</div>')
    return templates.TemplateResponse("tokens.html", ctx)
