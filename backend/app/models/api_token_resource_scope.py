import uuid

from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ApiTokenResourceScope(Base):
    """Only populated when the token's scope_type is 'selected_resources' - lets a
    token be scoped to an arbitrary subset of a client's resources (e.g. one host
    and one storage entry) rather than the whole client."""

    __tablename__ = "api_token_resource_scopes"

    token_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_tokens.id", ondelete="CASCADE"), primary_key=True
    )
    resource_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True
    )
