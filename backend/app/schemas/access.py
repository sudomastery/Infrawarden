import uuid
from datetime import datetime

from pydantic import BaseModel


class AccessGrantIn(BaseModel):
    user_id: uuid.UUID
    wrapped_data_key: str  # base64, crypto_box_seal'd to user_id's public key


class AccessGrantOut(BaseModel):
    user_id: uuid.UUID
    email: str
    granted_by_user_id: uuid.UUID
    granted_at: datetime


class PromoteResponse(BaseModel):
    user_id: uuid.UUID
    clients_needing_reconciliation: list[uuid.UUID]
