import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ResourceUserState(Base):
    """Per-viewer 'which version is MY instance on' pointer - implements both the
    PR-style accept/ignore flow and the personal-hide flow. See
    docs/ARCHITECTURE.md for the full lifecycle."""

    __tablename__ = "resource_user_states"

    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)

    current_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resource_versions.id"), nullable=False
    )
    last_seen_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resource_versions.id"), nullable=True
    )

    # Set when a non-owner grant holder "deletes" the resource: removes it from
    # only their own view. Touches nothing else - the resource stays fully alive
    # for every other grant holder.
    hidden_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
