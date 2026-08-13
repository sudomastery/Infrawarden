import uuid
from datetime import datetime

from pydantic import BaseModel, model_validator

from app.models.api_token import TokenScopeType

# 30 minutes / 1 hour / 1 day, per the product spec. Kept as an explicit allowlist
# rather than an arbitrary integer so a client can't mint a year-long token.
ALLOWED_TTL_SECONDS = {1800, 3600, 86400}


class TokenCreate(BaseModel):
    token_id: uuid.UUID  # client-generated - see ApiToken model docstring
    scope_type: TokenScopeType
    resource_ids: list[uuid.UUID] | None = None
    ttl_seconds: int
    token_hash: str
    wrapped_data_key: str  # base64
    wrapped_data_key_nonce: str  # base64

    @model_validator(mode="after")
    def _validate(self) -> "TokenCreate":
        if self.ttl_seconds not in ALLOWED_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be one of {sorted(ALLOWED_TTL_SECONDS)}")
        if self.scope_type == TokenScopeType.selected_resources and not self.resource_ids:
            raise ValueError("resource_ids is required when scope_type is selected_resources")
        return self


class TokenCreated(BaseModel):
    id: uuid.UUID
    scope_type: TokenScopeType
    resource_ids: list[uuid.UUID]
    expires_at: datetime


class TokenOut(BaseModel):
    id: uuid.UUID
    created_by_user_id: uuid.UUID
    scope_type: TokenScopeType
    resource_ids: list[uuid.UUID]
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class AgentDocResponse(BaseModel):
    client_name: str
    rendered_markdown: str
    expires_at: datetime
