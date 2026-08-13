import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ResourceType(str, enum.Enum):
    host = "host"
    vm = "vm"
    storage = "storage"
    network_device = "network_device"


class ResourceStatus(str, enum.Enum):
    active = "active"
    pending_delete = "pending_delete"


class Resource(Base):
    """Metadata shell over an append-only ResourceVersion history - holds no
    ciphertext itself. See docs/ARCHITECTURE.md for the per-user version
    divergence and deletion models this table participates in."""

    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    resource_type: Mapped[ResourceType] = mapped_column(Enum(ResourceType, name="resource_type"), nullable=False)

    # The resource's owner for deletion purposes - see ResourceStatus semantics below.
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Denormalized pointer to the current head version, updated transactionally on
    # every new version insert - avoids a MAX(created_at) query on every list view.
    # Nullable only momentarily during the create-resource transaction.
    latest_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("resource_versions.id", use_alter=True, name="fk_resources_latest_version_id"),
        nullable=True,
    )

    status: Mapped[ResourceStatus] = mapped_column(
        Enum(ResourceStatus, name="resource_status"), nullable=False, default=ResourceStatus.active
    )
    deleted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
