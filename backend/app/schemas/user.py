import uuid

from pydantic import BaseModel

from app.models.user import UserRole, UserStatus


class UserPublic(BaseModel):
    """Safe-to-list fields for the sharing picker - never wrapped key material."""

    id: uuid.UUID
    email: str
    public_key: str  # base64


class UserMe(BaseModel):
    id: uuid.UUID
    email: str
    role: UserRole
    status: UserStatus
    public_key: str  # base64
    wrapped_private_key: str  # base64
    wrapped_private_key_nonce: str  # base64
    kdf_salt: str  # base64
    kdf_ops_limit: int
    kdf_mem_limit: int
