"""Gateway-facing token validation endpoint.

This endpoint is NOT session-authenticated. It is called by the gateway
on every cache-miss, authenticated via HMAC-SHA256 request signing (see
portal.auth.hmac_auth). Without caller authentication this would be a
token oracle — an attacker could probe `tok_` values and harvest user
identities for valid ones.

The response updates ApiToken.last_used_at on the portal, but note that
the gateway caches valid responses (~60s), so last_used_at is only a
best-effort "last seen by portal" indicator for actively-used tokens.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth.hmac_auth import require_valid_hmac
from portal.auth.tokens import hash_token
from portal.db.models import ApiToken, User
from portal.db.session import get_db

router = APIRouter(prefix="/api/tokens", tags=["validate"])


class ValidateRequest(BaseModel):
    token: str


class ValidateResponse(BaseModel):
    valid: bool
    user_id: str | None = None
    email: str | None = None
    role: str | None = None


@router.post(
    "/validate",
    response_model=ValidateResponse,
    dependencies=[Depends(require_valid_hmac)],
)
async def validate_token(
    payload: ValidateRequest,
    db: AsyncSession = Depends(get_db),
) -> ValidateResponse:
    token_hash = hash_token(payload.token)
    stmt = (
        select(ApiToken, User)
        .join(User, User.id == ApiToken.user_id)
        .where(ApiToken.token_hash == token_hash)
    )
    result = await db.execute(stmt)
    row = result.first()
    if row is None:
        return ValidateResponse(valid=False)

    token, user = row
    if token.is_revoked:
        return ValidateResponse(valid=False)
    if token.expires_at is not None and token.expires_at <= datetime.now(timezone.utc):
        return ValidateResponse(valid=False)
    if not user.is_active:
        return ValidateResponse(valid=False)

    token.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    return ValidateResponse(
        valid=True,
        user_id=str(user.id),
        email=user.email,
        role=user.role,
    )
