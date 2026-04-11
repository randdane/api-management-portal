"""Audit log helper.

Every mutation in the portal should call log_action() to create an
append-only record. The details JSONB column is a catch-all for context
that does not fit in resource_type/resource_id.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from portal.db.models import AuditLog


async def log_action(
    db: AsyncSession,
    *,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    row = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
    )
    db.add(row)
    await db.flush()
