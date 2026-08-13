import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_grant, get_current_user
from app.core.encoding import b64decode
from app.db.session import get_db
from app.models.api_token import ApiToken, TokenScopeType
from app.models.api_token_resource_scope import ApiTokenResourceScope
from app.models.resource import Resource, ResourceStatus
from app.models.user import User
from app.schemas.token import TokenCreate, TokenCreated, TokenOut

router = APIRouter(prefix="/clients/{client_id}/tokens", tags=["tokens"])


@router.post("", response_model=TokenCreated)
async def create_token(
    client_id: uuid.UUID,
    body: TokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TokenCreated:
    await get_client_grant(client_id, current_user, db)

    resource_ids: list[uuid.UUID] = []
    if body.scope_type == TokenScopeType.selected_resources:
        resources = await db.scalars(
            select(Resource).where(
                Resource.id.in_(body.resource_ids),
                Resource.client_id == client_id,
                Resource.status == ResourceStatus.active,
            )
        )
        found = list(resources)
        if len(found) != len(set(body.resource_ids)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more resource_ids don't belong to this client or aren't active",
            )
        resource_ids = [r.id for r in found]

    existing = await db.get(ApiToken, body.token_id)
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token_id already in use")

    token = ApiToken(
        id=body.token_id,
        token_hash=body.token_hash,
        client_id=client_id,
        created_by_user_id=current_user.id,
        scope_type=body.scope_type,
        wrapped_data_key=b64decode(body.wrapped_data_key),
        wrapped_data_key_nonce=b64decode(body.wrapped_data_key_nonce),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds),
    )
    db.add(token)
    for resource_id in resource_ids:
        db.add(ApiTokenResourceScope(token_id=token.id, resource_id=resource_id))

    await db.commit()
    return TokenCreated(
        id=token.id, scope_type=token.scope_type, resource_ids=resource_ids, expires_at=token.expires_at
    )


async def _resource_ids_for(db: AsyncSession, token: ApiToken) -> list[uuid.UUID]:
    if token.scope_type == TokenScopeType.all_resources:
        return []
    scopes = await db.scalars(
        select(ApiTokenResourceScope.resource_id).where(ApiTokenResourceScope.token_id == token.id)
    )
    return list(scopes)


@router.get("", response_model=list[TokenOut])
async def list_tokens(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[TokenOut]:
    await get_client_grant(client_id, current_user, db)
    tokens = await db.scalars(select(ApiToken).where(ApiToken.client_id == client_id))
    out = []
    for token in tokens:
        out.append(
            TokenOut(
                id=token.id,
                created_by_user_id=token.created_by_user_id,
                scope_type=token.scope_type,
                resource_ids=await _resource_ids_for(db, token),
                expires_at=token.expires_at,
                revoked_at=token.revoked_at,
                last_used_at=token.last_used_at,
                created_at=token.created_at,
            )
        )
    return out


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(
    client_id: uuid.UUID,
    token_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    await get_client_grant(client_id, current_user, db)
    token = await db.get(ApiToken, token_id)
    if token is None or token.client_id != client_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    token.revoked_at = datetime.now(timezone.utc)
    # Physical revocation, matching the expiry path - nulled now, not just flagged.
    token.wrapped_data_key = None
    token.wrapped_data_key_nonce = None
    await db.commit()
