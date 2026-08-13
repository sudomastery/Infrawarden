import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models.user import UserRole


class InviteCreate(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.user


class InviteCreated(BaseModel):
    id: uuid.UUID
    email: str
    role: UserRole
    expires_at: datetime
    token: str  # raw token, shown exactly once - never persisted server-side


class InvitePublic(BaseModel):
    email: str
    role: UserRole
    expires_at: datetime


class InviteAccept(BaseModel):
    public_key: str  # base64
    wrapped_private_key: str  # base64
    wrapped_private_key_nonce: str  # base64
    kdf_salt: str  # base64
    kdf_ops_limit: int
    kdf_mem_limit: int
    auth_hash: str
