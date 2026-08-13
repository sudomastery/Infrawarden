import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.client_timeline_entry import TimelineEntrySource


class TimelineEntryCreate(BaseModel):
    ciphertext: str  # base64
    nonce: str  # base64
    resource_id: uuid.UUID | None = None


class TimelineEntryOut(BaseModel):
    id: uuid.UUID
    client_id: uuid.UUID
    resource_id: uuid.UUID | None
    source: TimelineEntrySource
    ciphertext: str  # base64
    nonce: str  # base64
    created_by_user_id: uuid.UUID | None
    created_at: datetime
