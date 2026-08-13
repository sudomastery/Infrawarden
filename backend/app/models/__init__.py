# Models are added here as they're implemented; importing this module
# registers every model's table on Base.metadata so Alembic autogenerate
# and create_all can see them.
from app.models.api_token import ApiToken, TokenScopeType
from app.models.api_token_resource_scope import ApiTokenResourceScope
from app.models.client import Client
from app.models.client_access_grant import ClientAccessGrant
from app.models.invite import Invite
from app.models.resource import Resource, ResourceStatus, ResourceType
from app.models.resource_note import ResourceNote
from app.models.resource_user_state import ResourceUserState
from app.models.resource_version import ResourceVersion
from app.models.user import User, UserRole, UserStatus

__all__ = [
    "User",
    "UserRole",
    "UserStatus",
    "Invite",
    "Client",
    "ClientAccessGrant",
    "Resource",
    "ResourceType",
    "ResourceStatus",
    "ResourceVersion",
    "ResourceUserState",
    "ResourceNote",
    "ApiToken",
    "TokenScopeType",
    "ApiTokenResourceScope",
]
