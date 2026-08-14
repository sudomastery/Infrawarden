import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_client_grant, get_current_user
from app.core.encoding import b64decode, b64encode
from app.db.session import get_db
from app.models.client import Client
from app.models.client_access_grant import ClientAccessGrant
from app.models.resource import Resource, ResourceStatus
from app.models.resource_user_state import ResourceUserState
from app.models.user import User, UserRole
from app.schemas.access import AccessGrantIn, AccessGrantOut
from app.schemas.client import ClientCreate, ClientDetail, ClientOut, ClientUpdate

router = APIRouter(prefix="/clients", tags=["clients"])


@router.post("", response_model=ClientDetail)
async def create_client(
    body: ClientCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ClientDetail:
    if len(body.grants) != len({g.user_id for g in body.grants}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Duplicate user_id in grants")

    grant_user_ids = {g.user_id for g in body.grants}
    if current_user.id not in grant_user_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must include a grant for yourself")

    # Must be EXACTLY the creator plus every current superadmin - not just "no
    # extra non-admins". A grant set that's missing a superadmin would silently
    # violate the "superadmins always have access to every client" guarantee,
    # with no later mechanism to detect or repair it (promotion reconciliation
    # only fires for users being newly promoted, not for admins omitted here).
    current_admin_ids = {u.id for u in await db.scalars(select(User).where(User.role == UserRole.admin))}
    required_ids = current_admin_ids | {current_user.id}
    if grant_user_ids != required_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grants must include yourself and every current superadmin, and no one else",
        )

    client = Client(name=body.name, description=body.description, created_by_user_id=current_user.id)
    db.add(client)
    await db.flush()

    caller_wrapped_key: str | None = None
    for grant_in in body.grants:
        db.add(
            ClientAccessGrant(
                client_id=client.id,
                user_id=grant_in.user_id,
                wrapped_data_key=b64decode(grant_in.wrapped_data_key),
                granted_by_user_id=current_user.id,
            )
        )
        if grant_in.user_id == current_user.id:
            caller_wrapped_key = grant_in.wrapped_data_key

    await db.commit()
    await db.refresh(client)

    return ClientDetail(
        id=client.id,
        name=client.name,
        description=client.description,
        created_by_user_id=client.created_by_user_id,
        created_at=client.created_at,
        updated_at=client.updated_at,
        wrapped_data_key=caller_wrapped_key,
    )


@router.get("", response_model=list[ClientDetail])
async def list_clients(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[ClientDetail]:
    rows = await db.execute(
        select(Client, ClientAccessGrant.wrapped_data_key)
        .join(ClientAccessGrant, ClientAccessGrant.client_id == Client.id)
        .where(ClientAccessGrant.user_id == current_user.id)
    )
    return [
        ClientDetail(
            id=client.id,
            name=client.name,
            description=client.description,
            created_by_user_id=client.created_by_user_id,
            created_at=client.created_at,
            updated_at=client.updated_at,
            wrapped_data_key=b64encode(wrapped_data_key),
        )
        for client, wrapped_data_key in rows.all()
    ]


@router.get("/{client_id}", response_model=ClientDetail)
async def get_client(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> ClientDetail:
    grant = await get_client_grant(client_id, current_user, db)
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    return ClientDetail(
        id=client.id,
        name=client.name,
        description=client.description,
        created_by_user_id=client.created_by_user_id,
        created_at=client.created_at,
        updated_at=client.updated_at,
        wrapped_data_key=b64encode(grant.wrapped_data_key),
    )


@router.patch("/{client_id}", response_model=ClientDetail)
async def update_client(
    client_id: uuid.UUID,
    body: ClientUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ClientDetail:
    """Only name/description - plaintext metadata the server already holds, no
    encryption involved. Any current grant holder may rename/redescribe, matching
    the same permission level already used for sharing."""
    grant = await get_client_grant(client_id, current_user, db)
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    if body.name is not None:
        client.name = body.name
    if body.description is not None:
        client.description = body.description
    await db.commit()
    await db.refresh(client)

    return ClientDetail(
        id=client.id,
        name=client.name,
        description=client.description,
        created_by_user_id=client.created_by_user_id,
        created_at=client.created_at,
        updated_at=client.updated_at,
        wrapped_data_key=b64encode(grant.wrapped_data_key),
    )


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> None:
    """Only ever deletes a client that has never had a resource created under it.
    Resources cascade-delete with the client at the DB level (see the Resource
    model), but resource_versions/resource_notes are supposed to be permanent -
    never truly destroyed even when a resource is 'deleted' (see
    docs/ARCHITECTURE.md's deletion model) - so a client-level hard delete must
    never be allowed to take that history down with it. Delete/archive every
    resource individually first if the client genuinely needs to go away."""
    await get_client_grant(client_id, current_user, db)
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    if client.created_by_user_id != current_user.id and current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the client owner or a superadmin can delete it")

    any_resource = await db.scalar(select(Resource.id).where(Resource.client_id == client_id).limit(1))
    if any_resource is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This client still has resources (including deleted ones, which are kept for recovery) - it can't be deleted while any exist",
        )

    await db.delete(client)
    await db.commit()


@router.post("/{client_id}/access", response_model=AccessGrantOut)
async def share_client_access(
    client_id: uuid.UUID,
    body: AccessGrantIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AccessGrantOut:
    """Any current grant holder can share access with a colleague - the grantor's
    browser must already have the data key unwrapped (it got there via their own
    grant) to seal a fresh copy for the new user. Also used, unmodified, as the
    per-client reconciliation step after promoting a user to superadmin."""
    await get_client_grant(client_id, current_user, db)

    target_user = await db.get(User, body.user_id)
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing = await db.scalar(
        select(ClientAccessGrant).where(
            ClientAccessGrant.client_id == client_id, ClientAccessGrant.user_id == body.user_id
        )
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already has access")

    grant = ClientAccessGrant(
        client_id=client_id,
        user_id=body.user_id,
        wrapped_data_key=b64decode(body.wrapped_data_key),
        granted_by_user_id=current_user.id,
    )
    db.add(grant)

    # The new grant holder starts in sync with every existing resource's current
    # head - nothing to reconcile, matching how a brand-new resource is seeded.
    resources = await db.scalars(
        select(Resource).where(Resource.client_id == client_id, Resource.status == ResourceStatus.active)
    )
    for resource in resources:
        db.add(
            ResourceUserState(
                resource_id=resource.id, user_id=body.user_id, current_version_id=resource.latest_version_id
            )
        )

    await db.commit()
    return AccessGrantOut(
        user_id=target_user.id,
        email=target_user.email,
        granted_by_user_id=current_user.id,
        granted_at=grant.granted_at,
    )


@router.get("/{client_id}/access", response_model=list[AccessGrantOut])
async def list_client_access(
    client_id: uuid.UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[AccessGrantOut]:
    await get_client_grant(client_id, current_user, db)
    rows = await db.execute(
        select(ClientAccessGrant, User.email)
        .join(User, User.id == ClientAccessGrant.user_id)
        .where(ClientAccessGrant.client_id == client_id)
    )
    return [
        AccessGrantOut(user_id=grant.user_id, email=email, granted_by_user_id=grant.granted_by_user_id, granted_at=grant.granted_at)
        for grant, email in rows.all()
    ]


@router.delete("/{client_id}/access/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client_access(
    client_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    await get_client_grant(client_id, current_user, db)

    target = await db.get(User, user_id)
    if target is not None and target.role == UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke a superadmin's access - it would break the guarantee that superadmins always have access to every client",
        )

    # Anyone can revoke their own access ("leave"). Revoking someone ELSE's
    # access is restricted to the client owner or a superadmin - otherwise any
    # colleague who was merely shared access could revoke the owner themselves.
    if user_id != current_user.id:
        client = await db.get(Client, client_id)
        if client is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
        if client.created_by_user_id != current_user.id and current_user.role != UserRole.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the client owner or a superadmin can revoke someone else's access",
            )

    grant = await db.scalar(
        select(ClientAccessGrant).where(
            ClientAccessGrant.client_id == client_id, ClientAccessGrant.user_id == user_id
        )
    )
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grant not found")
    await db.delete(grant)

    # Clean up this user's per-resource state too - otherwise re-sharing with
    # them later collides on the (resource_id, user_id) primary key. They start
    # fresh in sync at the current head if/when they're re-granted, which is the
    # right semantics anyway (not resuming a potentially very stale pointer).
    await db.execute(
        delete(ResourceUserState).where(
            ResourceUserState.user_id == user_id,
            ResourceUserState.resource_id.in_(select(Resource.id).where(Resource.client_id == client_id)),
        )
    )

    await db.commit()
