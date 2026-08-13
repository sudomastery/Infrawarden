import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, LargeBinary, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TimelineEntrySource(str, enum.Enum):
    manual = "manual"
    email = "email"
    future = "future"


class ClientTimelineEntry(Base):
    """Append-only, client-level activity log - deliberately separate from
    ResourceNote, which is per-resource freeform narrative. This table's real
    purpose is to give the (not-yet-built) email-capture pipeline a stable place
    to write into later (source='email') without a schema change; MVP only
    populates it via manual entries. See docs/ARCHITECTURE.md."""

    __tablename__ = "client_timeline_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resources.id", ondelete="CASCADE"), nullable=True
    )
    source: Mapped[TimelineEntrySource] = mapped_column(
        Enum(TimelineEntrySource, name="timeline_entry_source"), nullable=False, default=TimelineEntrySource.manual
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Null for automated sources (e.g. a future email-summarization job) - there is
    # no human author for those.
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
