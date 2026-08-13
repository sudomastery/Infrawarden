import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, LargeBinary, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"


class UserStatus(str, enum.Enum):
    invited = "invited"
    active = "active"
    disabled = "disabled"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.user)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"), nullable=False, default=UserStatus.invited
    )

    # Client-generated X25519 keypair. Public key is not secret; the private key
    # is only ever stored wrapped (AEAD-encrypted with a key derived from the
    # user's master password) - the server never sees the plaintext private key.
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_private_key_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Argon2id parameters used to derive the master-password stretch key client-side.
    # Stored per-user (not read from server config) so they can be migrated later
    # without breaking existing users.
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kdf_ops_limit: Mapped[int] = mapped_column(nullable=False)
    kdf_mem_limit: Mapped[int] = mapped_column(nullable=False)

    # Server-side rehash (argon2-cffi) of the client-computed login verifier.
    # Never the master password or the stretch key derived from it.
    auth_hash: Mapped[str] = mapped_column(String, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
