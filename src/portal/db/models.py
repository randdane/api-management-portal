import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)

    # Password auth: populated for local accounts, null for OAuth-only users.
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    # OAuth identity: populated if the account was linked via an external IdP.
    # The partial unique index below enforces that a given (provider, subject)
    # pair cannot be linked to more than one local user.
    oauth_provider: Mapped[str | None] = mapped_column(Text, nullable=True)
    oauth_subject: Mapped[str | None] = mapped_column(Text, nullable=True)

    role: Mapped[str] = mapped_column(
        # Use PgEnum (postgresql.ENUM — the *native* dialect type) with
        # create_type=False.  sa.Enum (the generic emulated type) silently drops
        # create_type=False when adapting to the PostgreSQL dialect because
        # adapt_emulated_to_native() only copies the flag for NativeForEmulated
        # subclasses.  PgEnum IS NativeForEmulated, so the flag is respected and
        # no spurious CREATE TYPE event fires when Alembic imports this metadata.
        PgEnum("admin", "user", name="user_role", create_type=False),
        nullable=False,
        default="user",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    api_tokens: Mapped[list["ApiToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Prevent the same external identity from being linked to two users.
        # Partial index: only enforced when both columns are populated.
        Index(
            "ux_users_oauth_identity",
            "oauth_provider",
            "oauth_subject",
            unique=True,
            postgresql_where=(
                "oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL"
            ),
        ),
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)

    # SHA-256 hex of the full plaintext token. The plaintext is shown once at
    # creation and never persisted.
    token_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False, index=True)

    # First 8 chars of the plaintext token (e.g., "tok_a3bf") so users can
    # identify tokens in the UI without ever re-exposing the secret.
    token_prefix: Mapped[str] = mapped_column(Text, nullable=False)

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Best-effort "last seen by portal" field. Because the gateway caches
    # successful validations in Redis (~60s TTL), most real uses do not reach
    # the portal, so this value is systematically stale for actively-used
    # tokens. The UI must label this as "last seen" rather than "last used".
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="api_tokens")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 of the session cookie value. Enables server-side invalidation
    # and means a DB dump does not leak live session cookies.
    session_token_hash: Mapped[str] = mapped_column(
        Text, unique=True, nullable=False, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="sessions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    user: Mapped["User | None"] = relationship()
