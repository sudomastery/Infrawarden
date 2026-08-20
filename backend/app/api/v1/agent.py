import hmac
import json
import uuid
from datetime import datetime, timezone

import nacl.exceptions
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import aead_decrypt, derive_token_wrap_key
from app.core.limiter import limiter
from app.core.security import hash_token_secret
from app.db.session import get_db
from app.models.api_token import ApiToken, TokenScopeType
from app.models.api_token_resource_scope import ApiTokenResourceScope
from app.models.client import Client
from app.models.resource import Resource, ResourceStatus
from app.models.resource_note import ResourceNote
from app.models.resource_user_state import ResourceUserState
from app.models.resource_version import ResourceVersion
from app.models.user import User
from app.schemas.token import AgentDocResponse
from app.services.rendering import RenderNote, RenderResource, render_client_doc
from app.services.token_service import check_and_maybe_expire

router = APIRouter(prefix="/agent", tags=["agent"])

_UNAUTHORIZED = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def _parse_bearer(authorization: str | None) -> tuple[str, bytes]:
    if not authorization or not authorization.startswith("Bearer "):
        raise _UNAUTHORIZED
    raw = authorization[len("Bearer ") :]
    if "." not in raw:
        raise _UNAUTHORIZED
    token_id_str, token_secret_hex = raw.split(".", 1)
    try:
        token_secret = bytes.fromhex(token_secret_hex)
    except ValueError:
        raise _UNAUTHORIZED
    return token_id_str, token_secret


@router.get("/doc", response_model=AgentDocResponse)
@limiter.limit("30/minute")
async def get_agent_doc(
    request: Request, authorization: str | None = Header(default=None), db: AsyncSession = Depends(get_db)
) -> AgentDocResponse:
    """The one endpoint an agent (via the MCP server) actually calls. No client id
    in the path or params - everything is derived from the token itself, so there
    is no IDOR-shaped mismatch to get wrong. See docs/ARCHITECTURE.md for the full
    reconciliation mechanism this implements."""
    token_id_str, token_secret = _parse_bearer(authorization)

    try:
        token_id = uuid.UUID(token_id_str)
    except ValueError:
        raise _UNAUTHORIZED

    token = await db.get(ApiToken, token_id)
    if token is None:
        raise _UNAUTHORIZED

    if not await check_and_maybe_expire(db, token):
        raise _UNAUTHORIZED

    if not hmac.compare_digest(hash_token_secret(token_secret), token.token_hash):
        raise _UNAUTHORIZED

    # wrapped_data_key can't be None here: check_and_maybe_expire already
    # confirmed the token is neither revoked nor expired, and both of those are
    # the only paths that null it out.
    try:
        token_wrap_key = derive_token_wrap_key(str(token.id), token_secret)
        data_key = aead_decrypt(token.wrapped_data_key, token.wrapped_data_key_nonce, token_wrap_key)
    except nacl.exceptions.CryptoError:
        raise _UNAUTHORIZED

    client = await db.get(Client, token.client_id)
    if client is None:
        raise _UNAUTHORIZED

    if token.scope_type == TokenScopeType.all_resources:
        resources = list(
            await db.scalars(
                select(Resource).where(Resource.client_id == token.client_id, Resource.status == ResourceStatus.active)
            )
        )
    else:
        scoped_ids = list(
            await db.scalars(select(ApiTokenResourceScope.resource_id).where(ApiTokenResourceScope.token_id == token.id))
        )
        resources = list(
            await db.scalars(select(Resource).where(Resource.id.in_(scoped_ids), Resource.status == ResourceStatus.active))
        )

    render_resources = []
    for resource in resources:
        # Render whatever version the TOKEN CREATOR's own state points to -
        # "the agent sees my instance," consistent with the per-user version
        # divergence model. Not necessarily the resource's latest version.
        state = await db.get(ResourceUserState, (resource.id, token.created_by_user_id))
        version_id = state.current_version_id if state else resource.latest_version_id
        version = await db.get(ResourceVersion, version_id)

        try:
            fields = json.loads(aead_decrypt(version.ciphertext, version.nonce, data_key))
        except nacl.exceptions.CryptoError:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not decrypt resource")

        notes_rows = await db.execute(
            select(ResourceNote, User.email)
            .join(User, User.id == ResourceNote.author_user_id)
            .where(ResourceNote.resource_id == resource.id)
            .order_by(ResourceNote.created_at)
        )
        notes = []
        for note, author_email in notes_rows.all():
            try:
                text = json.loads(aead_decrypt(note.ciphertext, note.nonce, data_key))
            except nacl.exceptions.CryptoError:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not decrypt resource")
            notes.append(RenderNote(text=text, author_email=author_email, created_at=note.created_at))

        render_resources.append(RenderResource(resource_type=resource.resource_type, fields=fields, notes=notes))

    token.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    markdown = render_client_doc(client.name, render_resources)
    return AgentDocResponse(client_name=client.name, rendered_markdown=markdown, expires_at=token.expires_at)
