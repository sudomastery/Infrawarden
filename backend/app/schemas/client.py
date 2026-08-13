import uuid
from datetime import datetime

from pydantic import BaseModel


class ClientGrantIn(BaseModel):
    user_id: uuid.UUID
    wrapped_data_key: str  # base64, crypto_box_seal'd to user_id's public key


class ClientCreate(BaseModel):
    name: str
    description: str | None = None
    # Must include the creator's own entry plus one entry per user who was a
    # superadmin at creation time - enforced server-side, not just trusted from
    # the client. See docs/ARCHITECTURE.md "Superadmin access model".
    grants: list[ClientGrantIn]


class ClientUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ClientOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_by_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class ClientDetail(ClientOut):
    wrapped_data_key: str  # base64 - the CALLER's own wrapped copy of the data key
