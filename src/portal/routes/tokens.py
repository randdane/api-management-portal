"""User-facing API token management: list, create, revoke."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth.dependencies import get_current_user
from portal.auth.tokens import generate_token
from portal.db.models import ApiToken, User
from portal.db.session import get_db
from portal.services.audit import log_action
from portal.sse import is_datastar_request, merge_fragments

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


class TokenOut(BaseModel):
    id: str
    name: str
    token_prefix: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    is_revoked: bool


class TokenCreateRequest(BaseModel):
    name: str
    expires_at: datetime | None = None


class TokenCreateResponse(BaseModel):
    token: str  # plaintext — shown once
    id: str
    name: str
    token_prefix: str
    expires_at: datetime | None


def _to_out(row: ApiToken) -> TokenOut:
    return TokenOut(
        id=str(row.id),
        name=row.name,
        token_prefix=row.token_prefix,
        created_at=row.created_at,
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        is_revoked=row.is_revoked,
    )


async def _get_user_tokens(user: User, db: AsyncSession) -> list[ApiToken]:
    stmt = (
        select(ApiToken)
        .where(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("", response_model=list[TokenOut])
async def list_tokens(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[TokenOut] | object:
    rows = await _get_user_tokens(user, db)
    if is_datastar_request(request):
        from fastapi.templating import Jinja2Templates

        templates = Jinja2Templates(directory="src/portal/templates")
        html = templates.get_template("fragments/token_list.html").render(
            {"request": request, "user": user, "tokens": rows}
        )
        return merge_fragments(f'<div id="token-list">{html}</div>')

    return [_to_out(row) for row in rows]


@router.post("", response_model=TokenCreateResponse)
async def create_token(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenCreateResponse | object:
    payload_data = await request.json()
    payload = TokenCreateRequest(
        name=payload_data.get("name") or payload_data.get("tokenName") or "Unnamed token",
        expires_at=(
            payload_data.get("expires_at")
            or payload_data.get("expiresAt")
            or payload_data.get("tokenExpiry")
        ),
    )

    plain, token_hash, token_prefix = generate_token()
    row = ApiToken(
        user_id=user.id,
        name=payload.name,
        token_hash=token_hash,
        token_prefix=token_prefix,
        expires_at=payload.expires_at,
        is_revoked=False,
    )
    db.add(row)
    await db.flush()

    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=user.id,
        action="token.created",
        resource_type="api_token",
        resource_id=str(row.id),
        details={"name": payload.name, "prefix": token_prefix},
        ip_address=ip,
    )
    await db.commit()
    await db.refresh(row)

    if is_datastar_request(request):
        from fastapi.templating import Jinja2Templates

        templates = Jinja2Templates(directory="src/portal/templates")
        tokens = await _get_user_tokens(user, db)
        ctx = {"request": request, "user": user, "tokens": tokens, "plain_token": plain}
        reveal_html = templates.get_template("fragments/token_created.html").render(ctx)
        list_html = templates.get_template("fragments/token_list.html").render(ctx)
        return merge_fragments(
            reveal_html + "\n" + f'<div id="token-list">{list_html}</div>'
        )

    return TokenCreateResponse(
        token=plain,
        id=str(row.id),
        name=row.name,
        token_prefix=row.token_prefix,
        expires_at=row.expires_at,
    )


@router.delete("/{token_id}")
async def revoke_token(
    token_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict | object:
    stmt = select(ApiToken).where(
        ApiToken.id == token_id, ApiToken.user_id == user.id
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="token_not_found"
        )
    if row.is_revoked:
        return {"status": "ok", "already_revoked": True}

    row.is_revoked = True
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=user.id,
        action="token.revoked",
        resource_type="api_token",
        resource_id=str(row.id),
        details={"prefix": row.token_prefix},
        ip_address=ip,
    )
    await db.commit()

    if is_datastar_request(request):
        from fastapi.templating import Jinja2Templates

        templates = Jinja2Templates(directory="src/portal/templates")
        tokens = await _get_user_tokens(user, db)
        html = templates.get_template("fragments/token_list.html").render(
            {"request": request, "user": user, "tokens": tokens}
        )
        return merge_fragments(f'<div id="token-list">{html}</div>')

    return {"status": "ok"}
