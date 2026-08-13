import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.resource import ResourceStatus, ResourceType


class ResourceCreate(BaseModel):
    resource_type: ResourceType
    ciphertext: str  # base64
    nonce: str  # base64


class ResourceVersionOut(BaseModel):
    id: uuid.UUID
    changed_by_user_id: uuid.UUID
    ciphertext: str  # base64
    nonce: str  # base64
    created_at: datetime


class ResourceOut(BaseModel):
    id: uuid.UUID
    client_id: uuid.UUID
    resource_type: ResourceType
    created_by_user_id: uuid.UUID
    status: ResourceStatus
    latest_version_id: uuid.UUID
    # The version the CALLER's own state currently points to - "my instance".
    current_version: ResourceVersionOut
    has_pending_change: bool
    hidden: bool
    created_at: datetime
    updated_at: datetime


class ResourceStateOut(BaseModel):
    current_version_id: uuid.UUID
    last_seen_version_id: uuid.UUID | None
    latest_version_id: uuid.UUID


class ResourceVersionCreate(BaseModel):
    ciphertext: str  # base64
    nonce: str  # base64


class ResourceNoteCreate(BaseModel):
    ciphertext: str  # base64
    nonce: str  # base64


class ResourceNoteOut(BaseModel):
    id: uuid.UUID
    author_user_id: uuid.UUID
    ciphertext: str  # base64
    nonce: str  # base64
    created_at: datetime


class DeletedResourceOut(BaseModel):
    id: uuid.UUID
    client_id: uuid.UUID
    client_name: str
    resource_type: ResourceType
    created_by_user_id: uuid.UUID
    deleted_by_user_id: uuid.UUID
    deleted_at: datetime
    latest_version: ResourceVersionOut
