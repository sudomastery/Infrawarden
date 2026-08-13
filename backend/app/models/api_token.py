import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TokenScopeType(str, enum.Enum):
    all_resources = "all_resources"
    selected_resources = "selected_resources"


class ApiToken(Base):
    """A scoped, TTL-limited credential an agent (Claude Code, via the MCP server)
    uses to fetch one client's infra doc. id is CLIENT-GENERATED (not a server
    default) because it's folded into the token_wrap_key derivation before the
    server ever sees the request - see docs/ARCHITECTURE.md for the full
    reconciliation mechanism this table implements."""

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scope_type: Mapped[TokenScopeType] = mapped_column(Enum(TokenScopeType, name="token_scope_type"), nullable=False)

    # The client's data key, re-wrapped under a key derived from the token's own
    # bearer secret at creation time - NOT under any server-held master key. Nulled
    # out (both columns) on first access after expiry or on explicit revoke, so
    # even a correct token_secret can no longer recover anything after that point -
    # physical expiry, not just an application-level check.
    wrapped_data_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_data_key_nonce: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
